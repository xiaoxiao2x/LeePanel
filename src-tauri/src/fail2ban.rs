//! Fail2ban 管理模块（业务层）。
//!
//! 设计要点（与 SSH 2FA 模块 tfa.rs 同范式：安装 + 配置系统文件 + 服务管理 + 备份回滚）：
//! - 全部操作在已连接会话上执行（复用 `session_exec_with_output`，自动获得 sudo 提权能力）；
//! - 配置只写面板专属 drop-in `/etc/fail2ban/jail.d/leepanel-<jail>.local`，不改写用户自有的
//!   `jail.local`，实现零残留（卸载 = 删除 drop-in 文件）；
//! - 写配置前备份、`fail2ban-client -t` 预检、预检失败自动回滚；
//! - ignoreip 强制注入本机回环（127.0.0.1/8 ::1），防误封；
//! - 所有写操作由 command 层调用 `audit_log` 记录审计。

use serde::{Serialize, Deserialize};
use crate::ssh::{SshSession, SshCache};

// ===== 数据结构 =====

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct F2bStatus {
    pub installed: bool,
    pub running: bool,
    pub version: String,
    pub jail_count: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct F2bJail {
    pub name: String,
    pub enabled: bool,
    pub currently_banned: i64,
    pub currently_failed: i64,
    pub total_banned: i64,
    pub total_failed: i64,
    pub maxretry: String,
    pub bantime: String,
    pub findtime: String,
    pub ignoreip: String,
}

/// 单个封禁 IP。`remaining`：>=0 为剩余秒数，-1 永久封禁，-2 未知。
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct F2bBan {
    pub ip: String,
    pub remaining: i64,
}

/// 只读探测：是否安装 / 版本 / 服务运行状态 / 活跃 jail 数。
pub async fn get_fail2ban_status(
    session: &SshSession,
    cache: &SshCache,
    session_id: &str,
) -> Result<F2bStatus, String> {
    if let Some(cached) = cache.get(session_id, "fail2ban_status", 15) {
        if let Ok(st) = serde_json::from_str::<F2bStatus>(&cached) {
            return Ok(st);
        }
    }

    let script = r#"
if command -v fail2ban-client >/dev/null 2>&1; then
  echo "INSTALLED=yes"
  VER=$(fail2ban-client version 2>/dev/null | head -1)
  echo "VERSION=$VER"
else
  echo "INSTALLED=no"
  echo "VERSION="
fi
if systemctl is-active --quiet fail2ban 2>/dev/null; then
  echo "RUNNING=yes"
else
  echo "RUNNING=no"
fi
COUNT=$(fail2ban-client status 2>/dev/null | awk '/Number of jail/{print $NF}')
echo "JAILCOUNT=${COUNT:-0}"
"#;
    let (stdout, _, code) = crate::ssh::session_exec_with_output(session, script, 15).await?;
    if code != 0 && !stdout.contains("INSTALLED=no") {
        return Err(format!("Failed to probe fail2ban status: {}", stdout.trim()));
    }

    let get = |key: &str| -> String {
        stdout.lines()
            .find(|l| l.starts_with(key))
            .map(|l| l.split_once('=').map(|(_, v)| v.trim().to_string()).unwrap_or_default())
            .unwrap_or_default()
    };

    let st = F2bStatus {
        installed: get("INSTALLED=") == "yes",
        running: get("RUNNING=") == "yes",
        version: get("VERSION="),
        jail_count: get("JAILCOUNT=").parse::<i64>().unwrap_or(0),
    };
    if let Ok(json) = serde_json::to_string(&st) {
        cache.put(session_id, "fail2ban_status", json);
    }
    Ok(st)
}

/// 列出**所有** jail（含未启用的），携带启用状态、关键参数与运行时统计。
/// 枚举来源：解析 fail2ban 配置文件（jail.conf → jail.d/*.conf → jail.local → jail.d/*.local，
/// 后者覆盖前者，与 fail2ban 官方读取顺序一致）。
pub async fn list_fail2ban_jails(
    session: &SshSession,
    cache: &SshCache,
    session_id: &str,
) -> Result<Vec<F2bJail>, String> {
    if let Some(cached) = cache.get(session_id, "fail2ban_jails", 15) {
        if let Ok(list) = serde_json::from_str::<Vec<F2bJail>>(&cached) {
            return Ok(list);
        }
    }

    let script = r#"#!/bin/bash
declare -A DEF
DEF[enabled]=false
DEF[maxretry]=5
DEF[bantime]=10m
DEF[findtime]=10m
DEF[ignoreip]="127.0.0.1/8 ::1"

declare -A JAILS ENABLED MAXRETRY BANTIME FINDTIME IGNOREIP

process_file() {
  local f="$1"
  [ -f "$f" ] || return
  local section="" line key val
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line//$'\r'/}"
    [[ "$line" =~ ^[[:space:]]*[#\;] ]] && continue
    if [[ "$line" =~ ^[[:space:]]*\[([^]]*)\] ]]; then
      section="${BASH_REMATCH[1]}"
      section="${section//[[:space:]]/}"
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      val="${val%"${val##*[![:space:]]}"}"
      case "$section" in
        DEFAULT)
          case "$key" in
            enabled) DEF[enabled]="$val" ;;
            maxretry) DEF[maxretry]="$val" ;;
            bantime) DEF[bantime]="$val" ;;
            findtime) DEF[findtime]="$val" ;;
            ignoreip) DEF[ignoreip]="$val" ;;
          esac ;;
        ""|INCLUDES|Init|Definition) ;;
        *)
          if [ -z "${JAILS[$section]+x}" ]; then
            JAILS["$section"]=1
            ENABLED["$section"]="${DEF[enabled]}"
            MAXRETRY["$section"]="${DEF[maxretry]}"
            BANTIME["$section"]="${DEF[bantime]}"
            FINDTIME["$section"]="${DEF[findtime]}"
            IGNOREIP["$section"]="${DEF[ignoreip]}"
          fi
          case "$key" in
            enabled) ENABLED["$section"]="$val" ;;
            maxretry) MAXRETRY["$section"]="$val" ;;
            bantime) BANTIME["$section"]="$val" ;;
            findtime) FINDTIME["$section"]="$val" ;;
            ignoreip) IGNOREIP["$section"]="$val" ;;
          esac ;;
      esac
    fi
  done < "$f"
}

process_file /etc/fail2ban/jail.conf
for f in /etc/fail2ban/jail.d/*.conf; do process_file "$f"; done
process_file /etc/fail2ban/jail.local
for f in /etc/fail2ban/jail.d/*.local; do process_file "$f"; done

for j in $(printf '%s\n' "${!JAILS[@]}" | sort); do
  en="${ENABLED[$j]}"
  S=$(fail2ban-client status "$j" 2>&1)
  if printf '%s\n' "$S" | grep -q 'Currently banned'; then
    CB=$(printf '%s\n' "$S" | awk -F'[\t]+' '/Currently banned/{print $2}' | tr -d '[:space:]')
    CF=$(printf '%s\n' "$S" | awk -F'[\t]+' '/Currently failed/{print $2}' | tr -d '[:space:]')
    TB=$(printf '%s\n' "$S" | awk -F'[\t]+' '/Total banned/{print $2}' | tr -d '[:space:]')
    TF=$(printf '%s\n' "$S" | awk -F'[\t]+' '/Total failed/{print $2}' | tr -d '[:space:]')
  else
    CB=0; CF=0; TB=0; TF=0
  fi
  echo "JAIL|$j|$en|${CB:-0}|${CF:-0}|${TB:-0}|${TF:-0}|${MAXRETRY[$j]}|${BANTIME[$j]}|${FINDTIME[$j]}|${IGNOREIP[$j]}"
done
"#;
    let (stdout, stderr, exit_code) = crate::ssh::session_exec_with_output(session, script, 30).await?;

    let mut list = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with("JAIL|") { continue; }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 11 { continue; }
        let enabled = parts[2].eq_ignore_ascii_case("true")
            || parts[2] == "1"
            || parts[2].eq_ignore_ascii_case("yes");
        list.push(F2bJail {
            name: parts[1].to_string(),
            enabled,
            currently_banned: parts[3].parse::<i64>().unwrap_or(0),
            currently_failed: parts[4].parse::<i64>().unwrap_or(0),
            total_banned: parts[5].parse::<i64>().unwrap_or(0),
            total_failed: parts[6].parse::<i64>().unwrap_or(0),
            maxretry: parts[7].to_string(),
            bantime: parts[8].to_string(),
            findtime: parts[9].to_string(),
            ignoreip: parts[10].to_string(),
        });
    }
    // 脚本本身出错时必须报错，不能静默返回空列表——否则 UI 会误显示"暂无 jail"。
    if list.is_empty() && exit_code != 0 {
        let detail = stderr
            .lines()
            .map(|l| l.trim())
            .find(|l| !l.is_empty())
            .unwrap_or("");
        return Err(format!(
            "fail2ban jail 枚举脚本执行失败 (exit {}): {}",
            exit_code,
            if detail.is_empty() { "无 stderr 输出" } else { detail }
        ));
    }
    if let Ok(json) = serde_json::to_string(&list) {
        cache.put(session_id, "fail2ban_jails", json);
    }
    Ok(list)
}

/// 列出某 jail 当前封禁的 IP 及剩余封禁时间。
/// 优先读 fail2ban 的 sqlite 库（timeofban + bantime）；库不可用时退化为仅 IP 列表（remaining=-2）。
pub async fn list_fail2ban_bans(
    session: &SshSession,
    jail: &str,
) -> Result<Vec<F2bBan>, String> {
    let script = format!(
        r#"#!/bin/bash
JAIL="{jail}"
DB="/var/lib/fail2ban/fail2ban.sqlite3"
if [ -f "$DB" ] && command -v python3 >/dev/null 2>&1; then
  python3 - "$JAIL" <<'PY'
import sqlite3, time, sys
jail = sys.argv[1]
now = int(time.time())
try:
    conn = sqlite3.connect('/var/lib/fail2ban/fail2ban.sqlite3')
    cur = conn.cursor()
    rows = cur.execute("SELECT ip, timeofban, bantime FROM bans WHERE jail = ?", (jail,)).fetchall()
    # bans 表没有唯一键、且会保留已过期的记录：先按 IP 取最新一条，再滤掉已过期的
    best = dict()
    for ip, t, bt in rows:
        if not ip:
            continue
        if ip not in best or t > best[ip][0]:
            best[ip] = (t, bt)
    out = []
    for ip, (t, bt) in best.items():
        if bt is None:
            rem = -2
        elif bt < 0:
            rem = -1
        else:
            rem = t + bt - now
            if rem <= 0:
                continue
        out.append((ip, rem))
    out.sort(key=lambda x: (x[1] < 0, x[1]))
    for ip, rem in out:
        print("BAN|%s|%s" % (ip, rem))
    conn.close()
except Exception:
    sys.exit(1)
PY
  if [ $? -eq 0 ]; then exit 0; fi
fi
fail2ban-client status "$JAIL" 2>/dev/null | sed -n '/Banned IP list:/,$p' | sed '1s/.*Banned IP list:[[:space:]]*//' | tr ' ' '\n' | awk 'NF{{print "BAN|" $1 "|-2"}}'
"#,
        jail = jail,
    );
    let (stdout, _, _) = crate::ssh::session_exec_with_output(session, &script, 15).await?;

    let mut bans = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with("BAN|") { continue; }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 3 { continue; }
        bans.push(F2bBan {
            ip: parts[1].to_string(),
            remaining: parts[2].parse::<i64>().unwrap_or(-2),
        });
    }
    Ok(bans)
}

/// 读取面板管理的 drop-in 配置原文（透明度展示用）。
pub async fn read_fail2ban_config(session: &SshSession) -> Result<String, String> {
    let script = r#"
for f in /etc/fail2ban/jail.d/leepanel-*.local; do
  [ -f "$f" ] || continue
  echo "== FILE: $f =="
  cat "$f"
  echo ""
done
if [ -f /etc/fail2ban/jail.local ]; then
  echo "== jail.local: present (user-managed, read-only) =="
else
  echo "== jail.local: absent =="
fi
"#;
    let (stdout, _, _) = crate::ssh::session_exec_with_output(session, script, 10).await?;
    Ok(stdout)
}

/// 安装 fail2ban（apt/dnf/yum 按发行版分支），装完 enable + start 服务。
pub async fn install_fail2ban(session: &SshSession) -> Result<String, String> {
    let script = r#"
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban 2>&1 || { echo "INSTALL_FAILED"; exit 1; }
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y fail2ban 2>&1 || { echo "INSTALL_FAILED"; exit 1; }
elif command -v yum >/dev/null 2>&1; then
  yum install -y fail2ban 2>&1 || { echo "INSTALL_FAILED"; exit 1; }
else
  echo "UNSUPPORTED_DISTRO"; exit 1
fi
command -v fail2ban-client >/dev/null 2>&1 || { echo "BINARY_MISSING"; exit 1; }
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true
echo "INSTALL_OK"
"#;
    let (stdout, _, code) = crate::ssh::session_exec_with_output(session, script, 600).await?;
    if code != 0 || !stdout.contains("INSTALL_OK") {
        return Err(format!("Fail2ban install failed: {}", stdout.trim()));
    }
    Ok(stdout.trim().to_string())
}

/// 卸载 fail2ban：停服 → 删除面板 drop-in → purge 包（零残留）。
pub async fn uninstall_fail2ban(session: &SshSession) -> Result<String, String> {
    let script = r#"
systemctl stop fail2ban 2>/dev/null || true
systemctl disable fail2ban 2>/dev/null || true
rm -f /etc/fail2ban/jail.d/leepanel-*.local 2>/dev/null || true
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get purge -y fail2ban 2>/dev/null || true
  apt-get autoremove -y 2>/dev/null || true
elif command -v dnf >/dev/null 2>&1; then
  dnf remove -y fail2ban 2>/dev/null || true
elif command -v yum >/dev/null 2>&1; then
  yum remove -y fail2ban 2>/dev/null || true
fi
echo "UNINSTALL_OK"
"#;
    let (stdout, _, code) = crate::ssh::session_exec_with_output(session, script, 600).await?;
    if code != 0 || !stdout.contains("UNINSTALL_OK") {
        return Err(format!("Fail2ban uninstall failed: {}", stdout.trim()));
    }
    Ok(stdout.trim().to_string())
}

/// 服务启停控制（action 由 command 层白名单校验：start/stop/restart/reload/status）。
pub async fn fail2ban_service_action(session: &SshSession, action: &str) -> Result<String, String> {
    let script = format!("systemctl {} fail2ban 2>&1 || true", action);
    let (stdout, stderr, code) = crate::ssh::session_exec_with_output(session, &script, 30).await?;
    if code != 0 {
        return Err(format!("Service action failed: {}{}", stdout.trim(), stderr.trim()));
    }
    Ok(stdout.trim().to_string())
}

/// 手动封禁一个 IP。
pub async fn fail2ban_ban_ip(session: &SshSession, jail: &str, ip: &str) -> Result<String, String> {
    let script = format!(r#"fail2ban-client set "{}" banip "{}" 2>&1"#, jail, ip);
    let (stdout, stderr, code) = crate::ssh::session_exec_with_output(session, &script, 30).await?;
    if code != 0 {
        return Err(format!("Ban failed: {}{}", stdout.trim(), stderr.trim()));
    }
    Ok(stdout.trim().to_string())
}

/// 手动解封一个 IP。
pub async fn fail2ban_unban_ip(session: &SshSession, jail: &str, ip: &str) -> Result<String, String> {
    let script = format!(r#"fail2ban-client set "{}" unbanip "{}" 2>&1"#, jail, ip);
    let (stdout, stderr, code) = crate::ssh::session_exec_with_output(session, &script, 30).await?;
    if code != 0 {
        return Err(format!("Unban failed: {}{}", stdout.trim(), stderr.trim()));
    }
    Ok(stdout.trim().to_string())
}

/// 写/更新某 jail 的面板专属 drop-in，预检通过后 reload；失败自动回滚。
pub async fn fail2ban_set_jail(
    session: &SshSession,
    jail: &str,
    enabled: bool,
    maxretry: &str,
    bantime: &str,
    findtime: &str,
    ignoreip: &str,
) -> Result<String, String> {
    let script = format!(
        r#"#!/bin/bash
FILE="/etc/fail2ban/jail.d/leepanel-{jail}.local"
mkdir -p /etc/fail2ban/jail.d
BK="/etc/leepanel-f2b-backups"
mkdir -p "$BK"
TS=$(date +%s)
[ -f "$FILE" ] && cp "$FILE" "$BK/leepanel-{jail}.local.$TS"

cat > "$FILE" <<'EOF'
# Managed by LeePanel
[{jail}]
enabled = {enabled}
maxretry = {maxretry}
bantime = {bantime}
findtime = {findtime}
ignoreip = 127.0.0.1/8 ::1 {ignoreip}
EOF

if ! fail2ban-client -t >/tmp/leepanel-f2b-test.log 2>&1; then
  if [ -f "$BK/leepanel-{jail}.local.$TS" ]; then
    cp "$BK/leepanel-{jail}.local.$TS" "$FILE"
  else
    rm -f "$FILE"
  fi
  echo "CONFIG_TEST_FAILED"
  cat /tmp/leepanel-f2b-test.log
  exit 1
fi
fail2ban-client reload 2>&1 || true
echo "CONFIGURED"
"#,
        jail = jail,
        enabled = enabled,
        maxretry = maxretry,
        bantime = bantime,
        findtime = findtime,
        ignoreip = ignoreip.trim(),
    );
    let (stdout, _, code) = crate::ssh::session_exec_with_output(session, &script, 30).await?;
    if code != 0 || !stdout.contains("CONFIGURED") {
        return Err(format!("Jail config failed (rolled back): {}", stdout.trim()));
    }
    Ok(stdout.trim().to_string())
}

/// 禁用/删除某 jail 的面板 drop-in（enabled=false 亦会移除，故直接删除文件并 reload）。
pub async fn fail2ban_remove_jail(session: &SshSession, jail: &str) -> Result<String, String> {
    let script = format!(
        r#"rm -f "/etc/fail2ban/jail.d/leepanel-{jail}.local" 2>/dev/null || true
fail2ban-client reload 2>&1 || true
echo "REMOVED"
"#,
        jail = jail,
    );
    let (stdout, _, code) = crate::ssh::session_exec_with_output(session, &script, 30).await?;
    if code != 0 || !stdout.contains("REMOVED") {
        return Err(format!("Remove jail failed: {}", stdout.trim()));
    }
    Ok(stdout.trim().to_string())
}
