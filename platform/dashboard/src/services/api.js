// ══════════════════════════════════════════════════════════════════════════════
//  SIEM Dashboard — Serviço de API
//  Encapsula todas as chamadas HTTP ao Indexer
// ══════════════════════════════════════════════════════════════════════════════

const BASE = import.meta.env.DEV ? 'http://localhost:8080' : '';

const get = (url) => fetch(BASE + url).then(r => { if (!r.ok) throw new Error(r.statusText); return r.json(); });
const post = (url, body) => fetch(BASE + url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const put  = (url, body) => fetch(BASE + url, { method: 'PUT',  headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const del  = (url)       => fetch(BASE + url, { method: 'DELETE' });

export const api = {
  // Stats
  overview:       () => get('/api/stats/overview'),
  timeline:       () => get('/api/stats/timeline'),

  // Events
  recentEvents:   (limit = 50) => get(`/api/events/recent?limit=${limit}`),
  eventDetail:    (id) => get(`/api/events/${id}`),
  search:         (params) => get(`/api/search?${new URLSearchParams(params)}`),

  // Alerts
  alerts:         (params = {}) => get(`/api/alerts?${new URLSearchParams(params)}`),
  updateAlert:    (id, status)  => put(`/api/alerts/${id}/status`, { status }),

  // Agents
  agents:         () => get('/api/agents'),

  // Rules (Legacy)
  rules:          () => get('/api/rules'),
  createRule:     (rule)  => post('/api/rules', rule).then(r => r.json()),
  updateRule:     (id, r) => put(`/api/rules/${id}`, r).then(r => r.json()),
  deleteRule:     (id)    => del(`/api/rules/${id}`),

  // Sigma Rules
  sigmaRules:       () => get('/api/sigma-rules'),
  sigmaRuleDetail:  (id) => get(`/api/sigma-rules/${id}`),
  createSigmaRule:  (yamlContent) => post('/api/sigma-rules', { yamlContent }).then(r => r.json()),
  updateSigmaRule:  (id, yamlContent) => put(`/api/sigma-rules/${id}`, { yamlContent }).then(r => r.json()),
  deleteSigmaRule:  (id) => del(`/api/sigma-rules/${id}`),
  testSigmaRule:    (yamlContent) => post('/api/sigma-rules/test', { yamlContent }).then(r => r.json()),
};
