//! Fail2ban 管理命令（薄包装层）。
//!
//! 职责：取会话 → 参数白名单校验 → 调 `crate::fail2ban` 业务函数 → 失效缓存 → 审计日志。
//! 只读查询不写审计；所有写操作写审计。

use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tauri::State;
use crate::{DbPool, ssh::SshManager, fail2ban};

#[tauri::command]
pub async fn fail2ban_get_status(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    session_id: String,
) -> Result<fail2ban::F2bStatus, String> {
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    drop(mgr);
    fail2ban::get_fail2ban_status(&session, &cache, &session_id).await
}

#[tauri::command]
pub async fn fail2ban_list_jails(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    session_id: String,
) -> Result<Vec<fail2ban::F2bJail>, String> {
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    drop(mgr);
    fail2ban::list_fail2ban_jails(&session, &cache, &session_id).await
}

#[tauri::command]
pub async fn fail2ban_list_bans(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    session_id: String,
    jail: String,
) -> Result<Vec<fail2ban::F2bBan>, String> {
    crate::permissions::validate_jail_name(&jail)?;
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    drop(mgr);
    fail2ban::list_fail2ban_bans(&session, &jail).await
}

#[tauri::command]
pub async fn fail2ban_read_config(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    session_id: String,
) -> Result<String, String> {
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    drop(mgr);
    fail2ban::read_fail2ban_config(&session).await
}

#[tauri::command]
pub async fn fail2ban_install(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    db: State<'_, DbPool>,
    session_id: String,
) -> Result<String, String> {
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    let host = session.connect_info.host.clone();
    let username = session.connect_info.username.clone();
    drop(mgr);
    let result = fail2ban::install_fail2ban(&session).await;
    cache.invalidate(&session_id, &["fail2ban_status", "fail2ban_jails"]);
    if let Ok(conn) = db.lock() {
        crate::audit::audit_log(
            &conn, &host, &username, "fail2ban_install", "install fail2ban",
            if result.is_ok() { "success" } else { "error" },
            &result.as_ref().err().cloned().unwrap_or_default(),
        );
    }
    result
}

#[tauri::command]
pub async fn fail2ban_uninstall(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    db: State<'_, DbPool>,
    session_id: String,
) -> Result<String, String> {
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    let host = session.connect_info.host.clone();
    let username = session.connect_info.username.clone();
    drop(mgr);
    let result = fail2ban::uninstall_fail2ban(&session).await;
    cache.invalidate(&session_id, &["fail2ban_status", "fail2ban_jails"]);
    if let Ok(conn) = db.lock() {
        crate::audit::audit_log(
            &conn, &host, &username, "fail2ban_uninstall", "uninstall fail2ban",
            if result.is_ok() { "success" } else { "error" },
            &result.as_ref().err().cloned().unwrap_or_default(),
        );
    }
    result
}

#[tauri::command]
pub async fn fail2ban_service_action(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    db: State<'_, DbPool>,
    session_id: String,
    action: String,
) -> Result<String, String> {
    crate::permissions::validate_service_action(&action)?;
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    let host = session.connect_info.host.clone();
    let username = session.connect_info.username.clone();
    drop(mgr);
    let result = fail2ban::fail2ban_service_action(&session, &action).await;
    cache.invalidate(&session_id, &["fail2ban_status"]);
    if let Ok(conn) = db.lock() {
        crate::audit::audit_log(
            &conn, &host, &username, "fail2ban_service_action",
            &format!("systemctl {} fail2ban", action),
            if result.is_ok() { "success" } else { "error" },
            &result.as_ref().err().cloned().unwrap_or_default(),
        );
    }
    result
}

#[tauri::command]
pub async fn fail2ban_ban_ip(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    db: State<'_, DbPool>,
    session_id: String,
    jail: String,
    ip: String,
) -> Result<String, String> {
    crate::permissions::validate_jail_name(&jail)?;
    crate::permissions::validate_ip(&ip)?;
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    let host = session.connect_info.host.clone();
    let username = session.connect_info.username.clone();
    drop(mgr);
    // 防锁死：拒绝封禁当前连接的对端 IP。
    if ip.trim() == host {
        return Err("Refusing to ban the IP of the current connection (lockout prevention)".to_string());
    }
    let result = fail2ban::fail2ban_ban_ip(&session, &jail, &ip).await;
    cache.invalidate(&session_id, &["fail2ban_jails"]);
    if let Ok(conn) = db.lock() {
        crate::audit::audit_log(
            &conn, &host, &username, "fail2ban_ban_ip",
            &format!("fail2ban-client set {} banip {}", jail, ip),
            if result.is_ok() { "success" } else { "error" },
            &result.as_ref().err().cloned().unwrap_or_default(),
        );
    }
    result
}

#[tauri::command]
pub async fn fail2ban_unban_ip(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    db: State<'_, DbPool>,
    session_id: String,
    jail: String,
    ip: String,
) -> Result<String, String> {
    crate::permissions::validate_jail_name(&jail)?;
    crate::permissions::validate_ip(&ip)?;
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    let host = session.connect_info.host.clone();
    let username = session.connect_info.username.clone();
    drop(mgr);
    let result = fail2ban::fail2ban_unban_ip(&session, &jail, &ip).await;
    cache.invalidate(&session_id, &["fail2ban_jails"]);
    if let Ok(conn) = db.lock() {
        crate::audit::audit_log(
            &conn, &host, &username, "fail2ban_unban_ip",
            &format!("fail2ban-client set {} unbanip {}", jail, ip),
            if result.is_ok() { "success" } else { "error" },
            &result.as_ref().err().cloned().unwrap_or_default(),
        );
    }
    result
}

#[tauri::command]
pub async fn fail2ban_set_jail(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    db: State<'_, DbPool>,
    session_id: String,
    jail: String,
    enabled: bool,
    maxretry: String,
    bantime: String,
    findtime: String,
    ignoreip: String,
) -> Result<String, String> {
    crate::permissions::validate_jail_name(&jail)?;
    crate::permissions::validate_pos_int(&maxretry)?;
    crate::permissions::validate_ban_time(&bantime)?;
    crate::permissions::validate_ban_time(&findtime)?;
    crate::permissions::validate_ignoreip(&ignoreip)?;
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    let host = session.connect_info.host.clone();
    let username = session.connect_info.username.clone();
    drop(mgr);
    let result = fail2ban::fail2ban_set_jail(&session, &jail, enabled, &maxretry, &bantime, &findtime, &ignoreip).await;
    cache.invalidate(&session_id, &["fail2ban_status", "fail2ban_jails"]);
    if let Ok(conn) = db.lock() {
        crate::audit::audit_log(
            &conn, &host, &username, "fail2ban_set_jail",
            &format!("set jail {} enabled={} maxretry={} bantime={} findtime={}", jail, enabled, maxretry, bantime, findtime),
            if result.is_ok() { "success" } else { "error" },
            &result.as_ref().err().cloned().unwrap_or_default(),
        );
    }
    result
}

#[tauri::command]
pub async fn fail2ban_remove_jail(
    ssh_mgr: State<'_, Arc<AsyncMutex<SshManager>>>,
    db: State<'_, DbPool>,
    session_id: String,
    jail: String,
) -> Result<String, String> {
    crate::permissions::validate_jail_name(&jail)?;
    let mgr = ssh_mgr.lock().await;
    let session = mgr.get_session(&session_id)?;
    let cache = mgr.cache.clone();
    let host = session.connect_info.host.clone();
    let username = session.connect_info.username.clone();
    drop(mgr);
    let result = fail2ban::fail2ban_remove_jail(&session, &jail).await;
    cache.invalidate(&session_id, &["fail2ban_status", "fail2ban_jails"]);
    if let Ok(conn) = db.lock() {
        crate::audit::audit_log(
            &conn, &host, &username, "fail2ban_remove_jail",
            &format!("remove jail {}", jail),
            if result.is_ok() { "success" } else { "error" },
            &result.as_ref().err().cloned().unwrap_or_default(),
        );
    }
    result
}
