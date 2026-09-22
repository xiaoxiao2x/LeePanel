import { useState, useEffect, useCallback, useMemo } from 'react'
import { invoke } from '../../sudoPrompt'
import { useTranslation } from 'react-i18next'

interface F2bStatus {
  installed: boolean
  running: boolean
  version: string
  jail_count: number
}

interface F2bJail {
  name: string
  enabled: boolean
  currently_banned: number
  currently_failed: number
  total_banned: number
  total_failed: number
  maxretry: string
  bantime: string
  findtime: string
  ignoreip: string
}

interface F2bBan {
  ip: string
  remaining: number
}

interface Fail2banPanelProps {
  sessionId: string | null
  connHost?: string
}

const JAIL_PRESETS = [
  { name: 'sshd', label: 'SSH (sshd)' },
  { name: 'nginx-http-auth', label: 'Nginx HTTP Auth' },
  { name: 'nginx-botsearch', label: 'Nginx Bot Search' },
  { name: 'apache-auth', label: 'Apache Auth' },
  { name: 'vsftpd', label: 'vsftpd' },
]

function formatRemaining(secs: number): string {
  if (secs < 0) return secs === -1 ? '∞' : '?'
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

export default function Fail2banPanel({ sessionId, connHost }: Fail2banPanelProps) {
  const { t } = useTranslation()
  const [status, setStatus] = useState<F2bStatus | null>(null)
  const [jails, setJails] = useState<F2bJail[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState<{ type: 'success' | 'info'; text: string } | null>(null)
  const [busy, setBusy] = useState('')

  // expand / ban list
  const [expanded, setExpanded] = useState<string | null>(null)
  const [bans, setBans] = useState<Record<string, F2bBan[]>>({})

  // dialogs
  const [editJail, setEditJail] = useState<F2bJail | null>(null)
  const [editFields, setEditFields] = useState({ enabled: true, maxretry: '5', bantime: '10m', findtime: '10m', ignoreip: '' })
  const [showAdd, setShowAdd] = useState(false)
  const [addName, setAddName] = useState('')
  const [banTarget, setBanTarget] = useState<{ jail: string } | null>(null)
  const [banIp, setBanIp] = useState('')
  const [confirmUninstall, setConfirmUninstall] = useState(false)

  const flash = (type: 'success' | 'info', text: string) => {
    setNotice({ type, text })
    setTimeout(() => setNotice(null), 3000)
  }

  const fetchStatus = useCallback(async () => {
    if (!sessionId) return
    try {
      setStatus(await invoke<F2bStatus>('fail2ban_get_status', { sessionId }))
    } catch (e) {
      setError(String(e))
    }
  }, [sessionId])

  const fetchJails = useCallback(async () => {
    if (!sessionId) return
    setLoading(true)
    setError('')
    try {
      setJails(await invoke<F2bJail[]>('fail2ban_list_jails', { sessionId }))
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [sessionId])

  const fetchBans = useCallback(async (jail: string) => {
    if (!sessionId) return
    try {
      const list = await invoke<F2bBan[]>('fail2ban_list_bans', { sessionId, jail })
      setBans(prev => ({ ...prev, [jail]: list }))
    } catch {
      setBans(prev => ({ ...prev, [jail]: [] }))
    }
  }, [sessionId])

  useEffect(() => { fetchStatus(); fetchJails() }, [fetchStatus, fetchJails])

  useEffect(() => {
    if (expanded) fetchBans(expanded)
  }, [expanded, fetchBans])

  const stats = useMemo(() => {
    const totalBanned = jails.reduce((s, j) => s + (j.currently_banned || 0), 0)
    const totalFailed = jails.reduce((s, j) => s + (j.currently_failed || 0), 0)
    const activeCount = jails.filter(j => j.enabled).length
    return { jailCount: jails.length, activeCount, totalBanned, totalFailed }
  }, [jails])

  const refreshAll = async () => { await Promise.all([fetchStatus(), fetchJails()]); if (expanded) await fetchBans(expanded) }

  const handleInstall = async () => {
    if (!sessionId) return
    setBusy('install')
    setError('')
    try {
      await invoke('fail2ban_install', { sessionId })
      flash('success', t('fail2ban.installOk'))
      await refreshAll()
    } catch (e) { setError(String(e)) } finally { setBusy('') }
  }

  const handleUninstall = async () => {
    if (!sessionId) return
    setBusy('uninstall')
    setError('')
    try {
      await invoke('fail2ban_uninstall', { sessionId })
      setConfirmUninstall(false)
      flash('success', t('fail2ban.uninstallOk'))
      await refreshAll()
    } catch (e) { setError(String(e)) } finally { setBusy('') }
  }

  const handleService = async (action: 'start' | 'stop' | 'restart' | 'reload') => {
    if (!sessionId) return
    setBusy('svc-' + action)
    setError('')
    try {
      await invoke('fail2ban_service_action', { sessionId, action })
      await fetchStatus()
    } catch (e) { setError(String(e)) } finally { setBusy('') }
  }

  const openEdit = (j: F2bJail) => {
    setEditJail(j)
    setEditFields({
      enabled: j.enabled,
      maxretry: j.maxretry || '5',
      bantime: j.bantime || '10m',
      findtime: j.findtime || '10m',
      ignoreip: (j.ignoreip || '').replace('127.0.0.1/8', '').replace('::1', '').trim(),
    })
  }

  const handleSaveJail = async () => {
    if (!sessionId || !editJail) return
    setBusy('save')
    setError('')
    try {
      await invoke('fail2ban_set_jail', {
        sessionId,
        jail: editJail.name,
        enabled: editFields.enabled,
        maxretry: editFields.maxretry.trim(),
        bantime: editFields.bantime.trim(),
        findtime: editFields.findtime.trim(),
        ignoreip: editFields.ignoreip.trim(),
      })
      setEditJail(null)
      flash('success', t('fail2ban.savedOk'))
      await refreshAll()
    } catch (e) { setError(String(e)) } finally { setBusy('') }
  }

  const handleAddJail = async () => {
    if (!sessionId || !addName.trim()) return
    setBusy('add')
    setError('')
    try {
      await invoke('fail2ban_set_jail', {
        sessionId,
        jail: addName.trim(),
        enabled: true,
        maxretry: '5',
        bantime: '10m',
        findtime: '10m',
        ignoreip: '',
      })
      setShowAdd(false)
      setAddName('')
      flash('success', t('fail2ban.addedOk'))
      await refreshAll()
    } catch (e) { setError(String(e)) } finally { setBusy('') }
  }

  const handleBan = async () => {
    if (!sessionId || !banTarget || !banIp.trim()) return
    setBusy('ban')
    setError('')
    try {
      await invoke('fail2ban_ban_ip', { sessionId, jail: banTarget.jail, ip: banIp.trim() })
      setBanTarget(null)
      setBanIp('')
      flash('success', t('fail2ban.banOk', { ip: banIp.trim() }))
      await fetchJails()
      if (expanded === banTarget.jail) await fetchBans(banTarget.jail)
    } catch (e) { setError(String(e)) } finally { setBusy('') }
  }

  const handleUnban = async (jail: string, ip: string) => {
    if (!sessionId) return
    setBusy('unban-' + ip)
    setError('')
    try {
      await invoke('fail2ban_unban_ip', { sessionId, jail, ip })
      flash('success', t('fail2ban.unbanOk', { ip }))
      await fetchJails()
      await fetchBans(jail)
    } catch (e) { setError(String(e)) } finally { setBusy('') }
  }

  if (!sessionId) return <div className="sp-empty">{t('common.connectFirst')}</div>

  const installed = status?.installed ?? false
  const running = status?.running ?? false
  const selfIp = connHost || ''

  return (
    <div className="firewall-panel">
      <div className="firewall-header">
        <h2>{t('fail2ban.title')}</h2>
        <div className="firewall-header-actions">
          {installed && (
            <button className="firewall-refresh" onClick={handleService.bind(null, 'reload')} disabled={!!busy || !running}>
              ↻ {t('fail2ban.reload')}
            </button>
          )}
          {installed && (
            <button className="firewall-refresh" onClick={handleService.bind(null, 'restart')} disabled={!!busy}>
              ⟳ {t('fail2ban.restart')}
            </button>
          )}
          <button className="firewall-refresh" onClick={refreshAll} disabled={loading}>
            {loading ? '...' : `↻ ${t('common.refresh')}`}
          </button>
        </div>
      </div>

      {error && <div className="firewall-error">{error}</div>}
      {notice && (
        <div className={`firewall-notice ${notice.type}`}>
          <span>{notice.type === 'success' ? '✅ ' : 'ℹ️ '}{notice.text}</span>
          <button className="firewall-notice-close" onClick={() => setNotice(null)}>✕</button>
        </div>
      )}

      {loading && !status && <div className="sp-loading">{t('fail2ban.detecting')}</div>}

      {status && (
        <>
          {/* 状态卡 */}
          <div className="firewall-status">
            <span className={`firewall-badge ${!installed ? 'none' : running ? 'active' : 'inactive'}`}>
              {!installed ? t('fail2ban.notInstalled') : running ? t('fail2ban.running') : t('fail2ban.stopped')}
              {installed && status.version ? ` · v${status.version}` : ''}
            </span>
            {installed ? (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <button
                  className="sidebar-confirm-btn"
                  onClick={() => handleService(running ? 'stop' : 'start')}
                  disabled={!!busy}
                >
                  {running ? t('fail2ban.stop') : t('fail2ban.start')}
                </button>
                <button
                  className="sidebar-confirm-btn danger"
                  onClick={() => setConfirmUninstall(true)}
                  disabled={!!busy}
                >
                  {t('fail2ban.uninstall')}
                </button>
              </div>
            ) : (
              <button className="sidebar-confirm-btn primary" onClick={handleInstall} disabled={busy === 'install'}>
                {busy === 'install' ? '...' : t('fail2ban.install')}
              </button>
            )}
          </div>

          {/* 统计 */}
          {installed && (
            <div className="fw-stats">
              <div className="fw-stat-card total">
                <span className="fw-stat-num">{stats.jailCount}</span>
                <span className="fw-stat-label">{t('fail2ban.totalJails')}</span>
              </div>
              <div className="fw-stat-card allow">
                <span className="fw-stat-num">{stats.activeCount}</span>
                <span className="fw-stat-label">{t('fail2ban.activeJails')}</span>
              </div>
              <div className="fw-stat-card deny">
                <span className="fw-stat-num">{stats.totalBanned}</span>
                <span className="fw-stat-label">{t('fail2ban.currentlyBanned')}</span>
              </div>
              <div className="fw-stat-card reject">
                <span className="fw-stat-num">{stats.totalFailed}</span>
                <span className="fw-stat-label">{t('fail2ban.currentlyFailed')}</span>
              </div>
            </div>
          )}

          {/* 工具条 */}
          {installed && (
            <div className="fw-toolbar">
              <div className="fw-toolbar-spacer" />
              <button className="firewall-add-btn" onClick={() => { setShowAdd(!showAdd); setAddName('') }}>
                {showAdd ? `✕ ${t('common.cancel')}` : t('fail2ban.addJail')}
              </button>
            </div>
          )}

          {/* 添加 jail 表单 */}
          {showAdd && installed && (
            <div className="firewall-add-form">
              <div className="firewall-form-row">
                <div className="firewall-form-group" style={{ flex: 1, minWidth: 180 }}>
                  <label>{t('fail2ban.jailName')}</label>
                  <input
                    value={addName}
                    onChange={(e) => setAddName(e.target.value)}
                    placeholder="sshd / nginx-http-auth"
                    onKeyDown={(e) => { if (e.key === 'Enter') handleAddJail() }}
                  />
                </div>
                <div className="firewall-form-group" style={{ alignSelf: 'flex-end' }}>
                  <button className="firewall-submit-btn" onClick={handleAddJail} disabled={busy === 'add' || !addName.trim()}>
                    {busy === 'add' ? '...' : t('common.create')}
                  </button>
                </div>
              </div>
              <div className="fw-quick-grid" style={{ marginTop: 10 }}>
                {JAIL_PRESETS.map(p => (
                  <button key={p.name} className="fw-quick-chip" onClick={() => setAddName(p.name)}>
                    <span className="fw-quick-label">{p.label}</span>
                    <span className="fw-quick-dot">+</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* jail 列表 */}
          {installed && (
            jails.length > 0 ? (
              <div className="firewall-rules-table">
                <div className="firewall-table-header">
                  <span className="fw-col-port">{t('fail2ban.jail')}</span>
                  <span className="fw-col-proto">{t('fail2ban.banned')}</span>
                  <span className="fw-col-action">{t('fail2ban.failed')}</span>
                  <span className="fw-col-source">{t('fail2ban.params')}</span>
                  <span className="fw-col-ops"></span>
                </div>
                {jails.map((j) => (
                  <div key={j.name}>
                    <div
                      className={`firewall-table-row ${expanded === j.name ? 'expanded' : ''}`}
                      style={{ opacity: j.enabled ? 1 : 0.55 }}
                      onClick={() => setExpanded(expanded === j.name ? null : j.name)}
                    >
                      <span className="fw-col-port" style={{ fontWeight: 600 }}>
                        {j.name}
                        {!j.enabled && <span style={{ opacity: 0.65, fontSize: 12, fontWeight: 400 }}> · {t('fail2ban.disabled')}</span>}
                      </span>
                      <span className="fw-col-proto">{j.enabled ? `${j.currently_banned} / ${j.total_banned}` : '—'}</span>
                      <span className={`fw-col-action ${j.currently_failed > 0 ? 'fw-action-deny' : ''}`}>{j.enabled ? `${j.currently_failed} / ${j.total_failed}` : '—'}</span>
                      <span className="fw-col-source fw-col-source-text" title={`maxretry=${j.maxretry} bantime=${j.bantime} findtime=${j.findtime}`}>
                        maxretry={j.maxretry} · bantime={j.bantime}
                      </span>
                      <span className="fw-col-ops" onClick={(e) => e.stopPropagation()}>
                        {j.enabled && (
                          <button className="fw-copy-btn" onClick={() => { setBanTarget({ jail: j.name }); setBanIp('') }} title={t('fail2ban.banIp')}>🛑</button>
                        )}
                        <button className="fw-copy-btn" onClick={() => openEdit(j)} title={t('fail2ban.edit')}>✎</button>
                      </span>
                    </div>
                    {expanded === j.name && j.enabled && (
                      <div className="fw-rule-detail">
                        <div className="fw-rule-detail-head">
                          <span>{t('fail2ban.bannedIps')}</span>
                          <button className="firewall-refresh" onClick={() => fetchBans(j.name)}>↻</button>
                        </div>
                        {(bans[j.name] ?? []).length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, padding: '8px 0' }}>
                            {(bans[j.name] ?? []).map(b => (
                              <span key={b.ip} className="fw-quick-chip" style={{ padding: '4px 10px' }}>
                                <span className="fw-quick-label">{b.ip}</span>
                                <span style={{ opacity: 0.72, fontSize: 12, marginLeft: 6 }} title={t('fail2ban.remaining')}>{formatRemaining(b.remaining)}</span>
                                <button
                                  className="fw-delete-btn"
                                  onClick={(e) => { e.stopPropagation(); handleUnban(j.name, b.ip) }}
                                  disabled={busy === 'unban-' + b.ip}
                                  title={t('fail2ban.unban')}
                                  style={{ marginLeft: 8 }}
                                >✕</button>
                              </span>
                            ))}
                          </div>
                        ) : (
                          <div className="fw-section-hint">{t('fail2ban.noBans')}</div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : error ? null : (
              <div className="firewall-empty">
                {t('fail2ban.noJails')}
              </div>
            )
          )}
        </>
      )}

      {/* 编辑 jail 弹窗 */}
      {editJail && (
        <div className="firewall-confirm-overlay" onClick={() => setEditJail(null)}>
          <div className="firewall-confirm-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="firewall-confirm-title">{t('fail2ban.editJail', { name: editJail.name })}</div>
            <div className="firewall-confirm-msg" style={{ display: 'grid', gap: 12, textAlign: 'left' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className={`firewall-toggle ${editFields.enabled ? 'on' : 'off'}`} onClick={() => setEditFields(f => ({ ...f, enabled: !f.enabled }))}>
                  <span className="toggle-track"><span className="toggle-thumb" /></span>
                </span>
                {t('fail2ban.enabled')}
              </label>
              {([
                { key: 'maxretry', label: t('fail2ban.maxretry') },
                { key: 'bantime', label: t('fail2ban.bantime') },
                { key: 'findtime', label: t('fail2ban.findtime') },
              ] as const).map(f => (
                <div key={f.key}>
                  <label style={{ display: 'block', marginBottom: 4, fontWeight: 500 }}>{f.label}</label>
                  <input
                    className="sidebar-edit-input"
                    value={editFields[f.key]}
                    onChange={(e) => setEditFields(prev => ({ ...prev, [f.key]: e.target.value }))}
                  />
                </div>
              ))}
              <div>
                <label style={{ display: 'block', marginBottom: 4, fontWeight: 500 }}>{t('fail2ban.ignoreip')}</label>
                <input
                  className="sidebar-edit-input"
                  value={editFields.ignoreip}
                  onChange={(e) => setEditFields(prev => ({ ...prev, ignoreip: e.target.value }))}
                  placeholder="e.g. 1.2.3.4 10.0.0.0/8"
                />
                <div className="fw-section-hint" style={{ marginTop: 4 }}>{t('fail2ban.ignoreipHint')}</div>
              </div>
            </div>
            <div className="firewall-confirm-actions">
              <button className="firewall-confirm-btn cancel" onClick={() => setEditJail(null)}>{t('common.cancel')}</button>
              <button className="firewall-confirm-btn primary" onClick={handleSaveJail} disabled={busy === 'save'}>
                {busy === 'save' ? '...' : t('common.save')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 封禁 IP 弹窗 */}
      {banTarget && (
        <div className="firewall-confirm-overlay" onClick={() => setBanTarget(null)}>
          <div className="firewall-confirm-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="firewall-confirm-title">{t('fail2ban.banIpTitle', { jail: banTarget.jail })}</div>
            <div className="firewall-confirm-msg">
              <input
                className="sidebar-edit-input"
                value={banIp}
                onChange={(e) => setBanIp(e.target.value)}
                placeholder="1.2.3.4"
                autoFocus
                onKeyDown={(e) => { if (e.key === 'Enter') handleBan() }}
              />
              {selfIp && banIp.trim() === selfIp && (
                <div className="fw-section-hint" style={{ marginTop: 8, color: 'var(--red)' }}>⚠ {t('fail2ban.selfBanWarning')}</div>
              )}
            </div>
            <div className="firewall-confirm-actions">
              <button className="firewall-confirm-btn cancel" onClick={() => setBanTarget(null)}>{t('common.cancel')}</button>
              <button className="firewall-confirm-btn danger" onClick={handleBan} disabled={busy === 'ban' || !banIp.trim()}>
                {busy === 'ban' ? '...' : t('fail2ban.ban')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 卸载确认 */}
      {confirmUninstall && (
        <div className="firewall-confirm-overlay" onClick={() => setConfirmUninstall(false)}>
          <div className="firewall-confirm-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="firewall-confirm-title">{t('fail2ban.uninstallTitle')}</div>
            <div className="firewall-confirm-msg">{t('fail2ban.uninstallWarning')}</div>
            <div className="firewall-confirm-actions">
              <button className="firewall-confirm-btn cancel" onClick={() => setConfirmUninstall(false)}>{t('common.cancel')}</button>
              <button className="firewall-confirm-btn danger" onClick={handleUninstall} disabled={busy === 'uninstall'}>
                {busy === 'uninstall' ? '...' : t('fail2ban.uninstall')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
