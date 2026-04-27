import { useState, useEffect } from 'react';
import { api } from '../services/api.js';
import Editor from 'react-simple-code-editor';
import Prism from 'prismjs';
import 'prismjs/components/prism-yaml';
import 'prismjs/themes/prism-dark.css'; // You might need to add a theme in index.html or install one

// ── Helpers ──────────────────────────────────────────────────────────────────
const SevBadge = ({ s }) => <span className={`sev sev-${(s||'raw').toLowerCase()}`}>{s || 'RAW'}</span>;

const fmtTime = (ts) => {
  if (!ts) return '—';
  const d = ts > 1e11 ? new Date(ts) : new Date(ts * 1000);
  return d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
};

const fmtDate = (ts) => {
  if (!ts) return '—';
  const d = ts > 1e11 ? new Date(ts) : new Date(ts * 1000);
  return d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
};

const sevColors = {
  CRITICAL: 'var(--sev-critical-fg)',
  ERROR:    'var(--sev-error-fg)',
  WARNING:  'var(--sev-warning-fg)',
  INFO:     'var(--sev-info-fg)',
  RAW:      'var(--sev-raw-fg)',
};

// ── SVG Icons ─────────────────────────────────────────────────────────────────
const IconPlus    = () => <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>;
const IconEdit    = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>;
const IconTrash   = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>;
const IconChevron = ({ left }) => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points={left ? "15 18 9 12 15 6" : "9 18 15 12 9 6"}/></svg>;
const IconClose   = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>;

// ── Field label map ──────────────────────────────────────────────────────────
const FIELD_LABELS = {
  source_ip: 'Source IP', ip_addresses: 'IP Addresses', port: 'Port',
  destination_port: 'Dest. Port', username: 'Username', root_involved: 'Root Involved',
  event_id: 'Windows Event ID', log_timestamp: 'Log Timestamp', protocol: 'Protocol',
  process: 'Process', service: 'Service', actions: 'Actions',
  threat_indicators: 'Threat Indicators', raw_length: 'Message Length',
  rule_id: 'Matched Rule', rule_name: 'Rule Name', category: 'Category',
};

// ── Client-side log parser (mirrors server parser.js) ────────────────────────
function parseLog(msg) {
  if (!msg || typeof msg !== 'string') return {};
  const f = {};
  const ips = [...new Set((msg.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g) || []))];
  if (ips.length) f.ip_addresses = ips;
  const srcIp = msg.match(/(?:from|rhost[= ])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);
  if (srcIp) f.source_ip = srcIp[1];
  const port = msg.match(/port\s+(\d+)/i);
  if (port) f.port = parseInt(port[1]);
  const dpt = msg.match(/DPT=(\d+)/);
  if (dpt) f.destination_port = parseInt(dpt[1]);
  const uPatterns = [/(?:for|for invalid user|for user)\s+(\S+)/i, /user[= ](\S+)/i, /account[: ]+(\S+)/i, /name=(\S+)/i];
  for (const p of uPatterns) { const m = msg.match(p); if (m && m[1]?.length > 1 && m[1] !== 'root') { f.username = m[1]; break; } }
  if (/\broot\b/.test(msg)) f.root_involved = true;
  const eid = msg.match(/EventID[= ](\d+)/i);
  if (eid) f.event_id = parseInt(eid[1]);
  const tsP = [/\[(\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2})\]/, /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/, /(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/];
  for (const p of tsP) { const m = msg.match(p); if (m) { f.log_timestamp = m[1]; break; } }
  const proto = msg.match(/\b(ssh2?|tcp|udp|icmp|http|https|ftp|rdp|smb)\b/i);
  if (proto) f.protocol = proto[1].toLowerCase();
  if (/\bsshd\b/i.test(msg)) f.service = 'sshd';
  if (/\bsudo\b/i.test(msg)) f.service = 'sudo';
  const proc = msg.match(/^(\w[\w.-]+)\[?\d*\]?:\s/);
  if (proc) f.process = proc[1];
  const acts = [];
  if (/failed|failure|denied|rejected|blocked/i.test(msg)) acts.push('denied');
  if (/accepted|success|opened|granted/i.test(msg)) acts.push('accepted');
  if (/locked|lockout/i.test(msg)) acts.push('lockout');
  if (/created|added|useradd/i.test(msg)) acts.push('created');
  if (/sudo|root|privilege|escalat/i.test(msg)) acts.push('privilege_escalation');
  if (acts.length) f.actions = acts;
  const threats = [];
  if (/mimikatz/i.test(msg)) threats.push('mimikatz');
  if (/meterpreter/i.test(msg)) threats.push('meterpreter');
  if (/psexec/i.test(msg)) threats.push('psexec');
  if (/netcat|ncat|nc\.exe/i.test(msg)) threats.push('netcat');
  if (/xmrig|minerd|cryptominer/i.test(msg)) threats.push('cryptominer');
  if (threats.length) f.threat_indicators = threats;
  return f;
}

// ── Reusable Parsed Fields Table ─────────────────────────────────────────────
function ParsedFieldsTable({ fields }) {
  if (!fields || Object.keys(fields).length === 0) return null;
  return (
    <div className="form-group">
      <label>Parsed Fields</label>
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: '6px', overflow: 'hidden' }}>
        <table className="data-table" style={{ margin: 0 }}>
          <tbody>
            {Object.entries(fields).map(([key, value]) => (
              <tr key={key}>
                <td style={{ fontWeight: 500, color: 'var(--text-2)', width: '160px', fontSize: '0.78rem' }}>
                  {FIELD_LABELS[key] || key}
                </td>
                <td style={{ fontFamily: 'JetBrains Mono, Consolas, monospace', fontSize: '0.78rem' }}>
                  {Array.isArray(value) ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {value.map((v, i) => <span key={i} className="col-pill">{String(v)}</span>)}
                    </div>
                  ) : typeof value === 'boolean' ? (
                    <span className={`col-pill ${value ? 'red' : ''}`}>{value ? 'Yes' : 'No'}</span>
                  ) : (
                    String(value)
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Event Detail Modal ───────────────────────────────────────────────────────
function EventDetailModal({ eventId, onClose }) {
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!eventId) return;
    setLoading(true);
    api.eventDetail(eventId)
      .then(d => { setDetail(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [eventId]);

  if (!eventId) return null;

  return (
    <div className="modal-overlay active" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-content" style={{ maxWidth: '720px' }}>
        <div className="modal-header">
          <h2>Event Details</h2>
          <button className="modal-close" onClick={onClose}><IconClose /></button>
        </div>
        <div className="modal-body" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
          {loading ? (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-3)' }}>Loading...</div>
          ) : detail ? (
            <>
              {/* Header info */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                <div className="form-group">
                  <label>Agent</label>
                  <div className="cell-mono" style={{ fontSize: '0.82rem' }}>{detail.agent_id}</div>
                </div>
                <div className="form-group">
                  <label>Type</label>
                  <div><span className="col-pill">{detail.log_type}</span></div>
                </div>
                <div className="form-group">
                  <label>Severity</label>
                  <div><SevBadge s={detail.severity} /></div>
                </div>
              </div>
              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label>Timestamp</label>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-2)' }}>{fmtDate(Number(detail.timestamp))}</div>
              </div>

              {/* Full raw message */}
              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label>Full Log Message</label>
                <pre style={{
                  background: 'var(--bg-2)', border: '1px solid var(--border)',
                  borderRadius: '6px', padding: '12px', fontSize: '0.78rem',
                  fontFamily: 'JetBrains Mono, Consolas, monospace', color: 'var(--text-1)',
                  whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: '1.5',
                  maxHeight: '200px', overflowY: 'auto', margin: 0
                }}>
                  {detail.message}
                </pre>
              </div>

              {/* Parsed fields */}
              <ParsedFieldsTable fields={detail.parsed_fields} />
            </>
          ) : (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-3)' }}>Event not found</div>
          )}
        </div>
        <div className="modal-footer">
          <button className="btn-secondary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}

// ── Overview ──────────────────────────────────────────────────────────────────
export function Overview() {
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [events, setEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const load = async () => {
    try {
      const [s, t, e] = await Promise.all([api.overview(), api.timeline(), api.recentEvents(60)]);
      setStats(s); setTimeline(t); setEvents(e);
    } catch {}
  };

  useEffect(() => { load(); const id = setInterval(load, 10000); return () => clearInterval(id); }, []);

  const bySev = stats?.events?.by_severity || [];
  const maxSev = Math.max(...bySev.map(b => b.count), 1);
  const maxTl  = Math.max(...timeline.map(t => (t.CRITICAL||0)+(t.ERROR||0)+(t.WARNING||0)+(t.INFO||0)+(t.RAW||0)), 1);

  return (
    <>
      {/* KPI Cards */}
      <div className="stat-row">
        {[
          { label: 'Events (1h)',    value: stats?.events?.last_hour ?? '—',     sub: `${(stats?.events?.total||0).toLocaleString('pt-BR')} total` },
          { label: 'Open Alerts',   value: stats?.alerts?.open ?? '—',           sub: `${stats?.alerts?.critical_open ?? 0} critical` },
          { label: 'Events (24h)',  value: stats?.events?.last_day?.toLocaleString('pt-BR') ?? '—', sub: '' },
          { label: 'Active Agents', value: stats?.agents?.active ?? '—',         sub: `${stats?.agents?.total ?? 0} registered` },
        ].map(c => (
          <div key={c.label} className="stat-card">
            <div className="stat-label">{c.label}</div>
            <div className="stat-value">{c.value}</div>
            {c.sub && <div className="stat-sub">{c.sub}</div>}
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '12px', marginBottom: '16px' }}>
        {/* Timeline */}
        <div className="panel">
          <div className="panel-header">
            <div><span className="panel-title">Event Timeline (24h)</span></div>
            <span className="live-pill"><span className="live-dot"/>Live</span>
          </div>
          <div className="timeline-chart">
            <div className="timeline-bars">
              {timeline.length > 0 ? timeline.slice(-36).map((pt, i) => {
                const total = (pt.CRITICAL||0)+(pt.ERROR||0)+(pt.WARNING||0)+(pt.INFO||0)+(pt.RAW||0);
                const h = Math.max(Math.round((total / maxTl) * 100), total > 0 ? 4 : 0);
                const cls = pt.CRITICAL > 0 ? 'critical' : pt.ERROR > 0 ? 'error' : 'normal';
                return (
                  <div key={i} className="tl-col" title={`${total} events`}>
                    <div className={`tl-bar ${cls}`} style={{ height: `${h}%` }}/>
                    <div className="tl-label">{i % 6 === 0 ? fmtTime(pt.timestamp).slice(0,5) : ''}</div>
                  </div>
                );
              }) : <div style={{color:'var(--text-3)',fontSize:'0.78rem',margin:'auto'}}>No data yet</div>}
            </div>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="panel">
          <div className="panel-header">
            <div><span className="panel-title">Severity Distribution</span></div>
          </div>
          <div className="severity-bars">
            {['CRITICAL','ERROR','WARNING','INFO','RAW'].map(sev => {
              const row = bySev.find(b => b.severity === sev);
              const count = row?.count || 0;
              const pct = (count / maxSev) * 100;
              return (
                <div key={sev} className="sev-bar-row">
                  <div className="sev-bar-label"><SevBadge s={sev}/></div>
                  <div className="sev-bar-track">
                    <div className="sev-bar-fill" style={{ width: `${pct}%`, background: sevColors[sev] }}/>
                  </div>
                  <div className="sev-bar-count">{count.toLocaleString('pt-BR')}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Events */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-title">Recent Events</span>
            <span className="live-pill"><span className="live-dot"/>Live</span>
          </div>
          <span className="badge-pill">{events.length}</span>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Time</th><th>Agent</th><th>Type</th><th>Severity</th><th>Message</th></tr></thead>
            <tbody>
              {events.length === 0 && <tr><td colSpan={5} className="empty-cell">No events yet — connect an agent to start collecting.</td></tr>}
              {events.map((e, i) => (
                <tr key={i} onClick={() => setSelectedEvent(e.id)} style={{ cursor: 'pointer' }} title="Click to view details">
                  <td className="cell-time">{fmtTime(e.timestamp)}</td>
                  <td className="cell-mono">{e.agent_id}</td>
                  <td><span className="col-pill">{e.log_type || 'generic'}</span></td>
                  <td><SevBadge s={e.severity}/></td>
                  <td className="msg-cell">{e.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <EventDetailModal eventId={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </>
  );
}

// ── Alerts ────────────────────────────────────────────────────────────────────
export function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);

  const load = () => api.alerts({ status, severity }).then(setAlerts).catch(() => {});
  useEffect(() => { load(); }, [status, severity]);

  return (
    <>
      <div className="panel">
        <div className="panel-header">
          <div><span className="panel-title">Alert Management</span></div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <select className="filter-select" value={status} onChange={e => setStatus(e.target.value)}>
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="closed">Closed</option>
            </select>
            <select className="filter-select" value={severity} onChange={e => setSeverity(e.target.value)}>
              <option value="">All severities</option>
              {['CRITICAL','ERROR','WARNING','INFO'].map(s => <option key={s}>{s}</option>)}
            </select>
          </div>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Time</th><th>Alert</th><th>Severity</th><th>Category</th><th>Agent</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
              {alerts.length === 0 && <tr><td colSpan={7} className="empty-cell">No alerts found with the selected filters.</td></tr>}
              {alerts.map(a => (
                <tr key={a.id} className={`alert-row alert-${a.severity?.toLowerCase()}`}
                    onClick={() => setSelectedAlert(a)} style={{ cursor: 'pointer' }} title="Click to view details">
                  <td className="cell-time">{fmtDate(a.timestamp)}</td>
                  <td>
                    <div style={{ fontWeight: 500, fontSize: '0.83rem' }}>{a.rule_name}</div>
                    <div className="cell-muted" style={{ fontSize: '0.75rem', marginTop: 2 }}>{a.description}</div>
                  </td>
                  <td><SevBadge s={a.severity}/></td>
                  <td><span className="cat-pill">{a.category}</span></td>
                  <td className="cell-mono">{a.agent_id || '—'}</td>
                  <td>
                    <span className={`status-pill status-${a.status === 'acknowledged' ? 'ack' : a.status}`}>
                      {a.status}
                    </span>
                  </td>
                  <td>
                    {a.status === 'open' && (
                      <button className="status-btn status-ack"
                        onClick={(e) => { e.stopPropagation(); api.updateAlert(a.id, 'acknowledged').then(load); }}>
                        Acknowledge
                      </button>
                    )}
                    {a.status === 'acknowledged' && (
                      <button className="status-btn status-closed"
                        onClick={(e) => { e.stopPropagation(); api.updateAlert(a.id, 'closed').then(load); }}>
                        Close
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <div className="modal-overlay active" onClick={e => e.target === e.currentTarget && setSelectedAlert(null)}>
          <div className="modal-content" style={{ maxWidth: '720px' }}>
            <div className="modal-header">
              <h2>Alert Details</h2>
              <button className="modal-close" onClick={() => setSelectedAlert(null)}><IconClose /></button>
            </div>
            <div className="modal-body" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
              {/* Header */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                <div className="form-group">
                  <label>Rule</label>
                  <div style={{ fontSize: '0.82rem', fontWeight: 500 }}>{selectedAlert.rule_name}</div>
                  <div className="cell-muted" style={{ fontSize: '0.72rem' }}>{selectedAlert.rule_id}</div>
                </div>
                <div className="form-group">
                  <label>Severity</label>
                  <div><SevBadge s={selectedAlert.severity} /></div>
                </div>
                <div className="form-group">
                  <label>Status</label>
                  <div>
                    <span className={`status-pill status-${selectedAlert.status === 'acknowledged' ? 'ack' : selectedAlert.status}`}>
                      {selectedAlert.status}
                    </span>
                  </div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                <div className="form-group">
                  <label>Category</label>
                  <div><span className="cat-pill">{selectedAlert.category}</span></div>
                </div>
                <div className="form-group">
                  <label>Agent</label>
                  <div className="cell-mono" style={{ fontSize: '0.82rem' }}>{selectedAlert.agent_id || '—'}</div>
                </div>
              </div>

              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label>Timestamp</label>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-2)' }}>{fmtDate(Number(selectedAlert.timestamp))}</div>
              </div>

              {/* Description */}
              <div className="form-group" style={{ marginBottom: '16px' }}>
                <label>Description</label>
                <div style={{
                  background: 'var(--bg-2)', border: '1px solid var(--border)',
                  borderRadius: '6px', padding: '12px', fontSize: '0.82rem',
                  color: 'var(--text-1)', lineHeight: '1.5'
                }}>
                  {selectedAlert.description || '—'}
                </div>
              </div>

              {/* Source Event */}
              {selectedAlert.source_event && (
                <div className="form-group" style={{ marginBottom: '16px' }}>
                  <label>Source Event</label>
                  <pre style={{
                    background: 'var(--bg-2)', border: '1px solid var(--border)',
                    borderRadius: '6px', padding: '12px', fontSize: '0.78rem',
                    fontFamily: 'JetBrains Mono, Consolas, monospace', color: 'var(--text-1)',
                    whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: '1.5',
                    maxHeight: '200px', overflowY: 'auto', margin: 0
                  }}>
                    {selectedAlert.source_event}
                  </pre>
                </div>
              )}

              {/* Parsed fields from source event */}
              <ParsedFieldsTable fields={parseLog(selectedAlert.source_event)} />

              {/* Recommended Action */}
              {selectedAlert.recommended_action && (
                <div className="form-group">
                  <label>Recommended Action</label>
                  <div style={{
                    background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.2)',
                    borderRadius: '6px', padding: '12px', fontSize: '0.82rem',
                    color: 'var(--accent)', lineHeight: '1.5'
                  }}>
                    {selectedAlert.recommended_action}
                  </div>
                </div>
              )}
            </div>
            <div className="modal-footer">
              {selectedAlert.status === 'open' && (
                <button className="btn-primary" onClick={() => {
                  api.updateAlert(selectedAlert.id, 'acknowledged').then(() => { load(); setSelectedAlert(null); });
                }}>Acknowledge</button>
              )}
              {selectedAlert.status === 'acknowledged' && (
                <button className="btn-primary" onClick={() => {
                  api.updateAlert(selectedAlert.id, 'closed').then(() => { load(); setSelectedAlert(null); });
                }}>Close Alert</button>
              )}
              <button className="btn-secondary" onClick={() => setSelectedAlert(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// ── Helpers: safe JSON parse (handles double-encoded strings) ─────────────────
function parseCollectors(raw) {
  if (!raw) return [];
  try {
    let parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    // Handle double-encoded: "\"[...]\""
    if (typeof parsed === 'string') parsed = JSON.parse(parsed);
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

// ── Agents ────────────────────────────────────────────────────────────────────
export function Agents() {
  const [agents, setAgents] = useState([]);

  useEffect(() => {
    const load = () => api.agents().then(data => setAgents(Array.isArray(data) ? data : [])).catch(() => {});
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, []);

  const isOnline = (a) => {
    const now = Math.floor(Date.now() / 1000);
    const lastSeen = Number(a.last_seen) || 0;
    return (now - lastSeen) < 120;
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <span className="panel-title">Connected Agents</span>
          <span className="badge-pill green">{agents.filter(isOnline).length} online</span>
        </div>
      </div>
      <div className="table-wrap">
        <table className="data-table">
          <thead><tr><th>Status</th><th>Agent ID</th><th>Hostname</th><th>IP Address</th><th>OS</th><th>Version</th><th>Collectors</th><th>Last Seen</th></tr></thead>
          <tbody>
            {agents.length === 0 && <tr><td colSpan={8} className="empty-cell">No agents registered yet. Install the agent on a machine to get started.</td></tr>}
            {agents.map(a => {
              const cols = parseCollectors(a.active_collectors);
              const online = isOnline(a);
              return (
                <tr key={a.agent_id}>
                  <td style={{ display:'flex', alignItems:'center', gap:'6px' }}>
                    <span className={`status-dot ${online ? 'on' : 'off'}`}/>
                    {online
                      ? <span className="online-pill">Online</span>
                      : <span style={{ fontSize: '0.72rem', color: 'var(--red)' }}>Offline</span>}
                  </td>
                  <td className="cell-mono">{a.agent_id}</td>
                  <td>{a.hostname || '—'}</td>
                  <td className="cell-mono">{a.ip_address || '—'}</td>
                  <td className="cell-muted">{a.os || '—'}</td>
                  <td className="cell-muted">{a.version || '—'}</td>
                  <td>{cols.map((c, i) => <span key={i} className="col-pill">{c}</span>)}</td>
                  <td className="cell-time">{fmtDate(Number(a.last_seen))}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Rules ─────────────────────────────────────────────────────────────────────
const emptyRule = { name: '', category: 'Authentication', severity: 'WARNING', pattern: '', description: '', action: '', enabled: true };
const CATEGORIES = ['Authentication','Privilege','Malware','Network','System','Correlation','Custom'];
const SEVERITIES  = ['CRITICAL','ERROR','WARNING','INFO'];

export function Rules() {
  const [rules, setRules]   = useState([]);
  const [modal, setModal]   = useState(false);
  const [editing, setEditing] = useState(null); // id of the rule
  const [yamlContent, setYamlContent] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const load = () => api.sigmaRules().then(setRules).catch(() => {});
  useEffect(() => { load(); }, []);

  const openNew  = () => { 
    setEditing(null); 
    setYamlContent('title: New Detection Rule\nid: sigma-new-001\nstatus: experimental\nlevel: medium\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        Image: \n    condition: selection\n');
    setErrorMsg('');
    setModal(true); 
  };
  
  const openEdit = async (r) => { 
    try {
      const detail = await api.sigmaRuleDetail(r.id);
      setEditing(detail.id); 
      setYamlContent(detail.rawYaml || ''); 
      setErrorMsg('');
      setModal(true);
    } catch (e) {
      alert('Failed to load rule content');
    }
  };

  const save = async () => {
    setErrorMsg('');
    try {
      if (editing) await api.updateSigmaRule(editing, yamlContent);
      else await api.createSigmaRule(yamlContent);
      setModal(false); 
      load();
    } catch (err) {
      setErrorMsg(err.message || 'Failed to save rule. Check YAML syntax.');
    }
  };

  const remove = async (id) => {
    if (!confirm('Permanently delete this rule?')) return;
    await api.deleteSigmaRule(id); 
    load();
  };

  const testRule = async () => {
    setErrorMsg('');
    try {
      const res = await api.testSigmaRule(yamlContent);
      alert(`Test successful! Rule matched ${res.matchCount} recent events.`);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to test rule.');
    }
  };

  const handleImport = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        await api.createSigmaRule(evt.target.result);
        load();
      } catch (err) {
        alert(err.message || 'Failed to import rule');
      }
    };
    reader.readAsText(file);
    e.target.value = ''; // Reset input
  };

  const handleExport = async (r) => {
    try {
      const detail = await api.sigmaRuleDetail(r.id);
      const blob = new Blob([detail.rawYaml], { type: 'text/yaml' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${r.id}.yml`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to export rule');
    }
  };

  return (
    <>
      <div className="panel">
        <div className="panel-header">
          <div>
            <span className="panel-title">Detection Rules (SIGMA)</span>
            <span className="badge-pill">{rules.length} loaded</span>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <label className="btn-secondary" style={{ display:'flex', alignItems:'center', gap:'6px', fontSize:'0.78rem', padding:'6px 12px', cursor:'pointer' }}>
              <input type="file" accept=".yml,.yaml" style={{ display: 'none' }} onChange={handleImport} />
              Import
            </label>
            <button className="btn-primary" style={{ display:'flex', alignItems:'center', gap:'6px', fontSize:'0.78rem', padding:'6px 12px' }} onClick={openNew}>
              <IconPlus /> New Rule
            </button>
          </div>
        </div>

        <div className="rules-grid">
          {rules.length === 0 && <div style={{ gridColumn: '1/-1', textAlign: 'center', color: 'var(--text-3)', padding: '40px', fontSize: '0.82rem' }}>No rules configured.</div>}
          {rules.map(r => (
            <div key={r.id} className={`rule-card ${(r.level||'').toLowerCase()}`}>
              <div className="rule-header">
                <span className="rule-id">{r.id}</span>
                <SevBadge s={(r.level || '').toUpperCase()} />
              </div>
              <div className="rule-title">{r.title}</div>
              <div className="rule-desc">{r.description || 'No description provided.'}</div>
              <div className="rule-meta">
                <span className="cat-pill">{r.logsource?.category || 'General'}</span>
                {r.status && <span className="cat-pill">{r.status}</span>}
              </div>
              <div className="rule-actions">
                <button className="btn-secondary btn-sm" onClick={() => handleExport(r)}>Export</button>
                <button className="btn-secondary btn-sm" onClick={() => openEdit(r)}>Edit YAML</button>
                <button className="btn-secondary btn-sm" onClick={() => remove(r.id)}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* YAML Editor Modal */}
      <div className={`modal-overlay ${modal ? 'active' : ''}`} onClick={e => e.target === e.currentTarget && setModal(false)}>
        <div className="modal-content" style={{ maxWidth: '800px', width: '100%' }}>
          <div className="modal-header">
            <h2>{editing ? 'Edit SIGMA Rule' : 'New SIGMA Rule'}</h2>
            <button className="modal-close" onClick={() => setModal(false)}>×</button>
          </div>
          <div className="modal-body" style={{ padding: 0 }}>
            {errorMsg && <div style={{ padding: '12px', background: 'rgba(239,68,68,0.1)', color: 'var(--sev-critical-fg)', fontSize: '0.82rem', borderBottom: '1px solid var(--border)' }}>{errorMsg}</div>}
            
            <div style={{ background: '#1e1e1e', height: '500px', overflowY: 'auto' }}>
              {(() => {
                const CodeEditor = Editor.default ? Editor.default : Editor;
                return (
                  <CodeEditor
                    value={yamlContent}
                    onValueChange={setYamlContent}
                    highlight={code => Prism.highlight(code, Prism.languages.yaml || Prism.languages.javascript || {}, 'yaml')}
                    padding={15}
                    style={{
                      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                      fontSize: 14,
                      minHeight: '100%',
                      color: '#d4d4d4',
                      backgroundColor: '#1e1e1e'
                    }}
                  />
                );
              })()}
            </div>
          </div>
          <div className="modal-footer" style={{ display: 'flex', justifyContent: 'space-between' }}>
            <div>
              <button className="btn-secondary" onClick={testRule} style={{ border: '1px solid var(--accent)', color: 'var(--accent)' }}>Test vs Recent Events</button>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button className="btn-secondary" onClick={() => setModal(false)}>Cancel</button>
              <button className="btn-primary" onClick={save}>{editing ? 'Save YAML' : 'Create Rule'}</button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

// ── Search ────────────────────────────────────────────────────────────────────
export function Search() {
  const [q, setQ]           = useState('');
  const [sev, setSev]       = useState('');
  const [logType, setLogType] = useState('');
  const [result, setResult] = useState(null);
  const [page, setPage]     = useState(1);
  const [selectedEvent, setSelectedEvent] = useState(null);

  const search = async (p = 1) => {
    const params = { page: p, per_page: 50 };
    if (q) params.q = q;
    if (sev) params.severity = sev;
    if (logType) params.log_type = logType;
    const res = await api.search(params);
    setResult(res); setPage(p);
  };

  return (
    <>
      <div className="panel search-panel">
        <div className="search-form">
          <input className="search-input-lg" value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && search(1)}
            placeholder="Search across log messages..."/>
          <select className="filter-select" value={sev} onChange={e => setSev(e.target.value)}>
            <option value="">All severities</option>
            {['CRITICAL','ERROR','WARNING','INFO','RAW'].map(s => <option key={s}>{s}</option>)}
          </select>
          <input className="filter-input" value={logType} onChange={e => setLogType(e.target.value)} placeholder="Log type"/>
          <button className="btn-search" onClick={() => search(1)}>Search</button>
        </div>
      </div>

      {result && (
        <div className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-title">Results</span>
              <span className="badge-pill">{result.pagination?.total?.toLocaleString('pt-BR')} found</span>
            </div>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Time</th><th>Agent</th><th>Type</th><th>Severity</th><th>Message</th></tr></thead>
              <tbody>
                {result.data?.length === 0 && <tr><td colSpan={5} className="empty-cell">No results found.</td></tr>}
                {result.data?.map((e, i) => (
                  <tr key={i} onClick={() => setSelectedEvent(e.id)} style={{ cursor: 'pointer' }} title="Click to view details">
                    <td className="cell-time">{fmtDate(e.timestamp)}</td>
                    <td className="cell-mono">{e.agent_id}</td>
                    <td><span className="col-pill">{e.log_type}</span></td>
                    <td><SevBadge s={e.severity}/></td>
                    <td className="msg-cell">{e.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {result.pagination?.total_pages > 1 && (
            <div className="pagination">
              <button className="page-btn" disabled={page <= 1} onClick={() => search(page - 1)}>
                <IconChevron left/> Previous
              </button>
              <span className="page-info">Page {page} of {result.pagination.total_pages}</span>
              <button className="page-btn" disabled={page >= result.pagination.total_pages} onClick={() => search(page + 1)}>
                Next <IconChevron/>
              </button>
            </div>
          )}
        </div>
      )}
      <EventDetailModal eventId={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </>
  );
}
