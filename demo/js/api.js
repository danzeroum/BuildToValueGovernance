/**
 * BuildToValue Trust OS Demo — API client
 * Todas as chamadas passam pelo proxy /api/* (sem expor a key)
 */

const API = {
  base: '/api',

  async _call(method, path, body) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(this.base + path, opts);
    const data = await res.json();
    return { status: res.status, ok: res.ok, data };
  },

  get:  (path)       => API._call('GET',  path, null),
  post: (path, body) => API._call('POST', path, body),

  // ── Endpoints BTV ─────────────────────────────────
  health:        ()     => API.get('/health'),
  decide:        (body) => API.post('/v1/decide', body),
  agentDecide:   (body) => API.post('/v1/agent/decide', body),

  ledgerQuery:   ()     => API.get('/v1/ledger/query'),
  ledgerStats:   ()     => API.get('/v1/ledger/stats'),

  appealsList:   ()     => API.get('/v1/appeals'),
  appealsCreate: (body) => API.post('/v1/appeals', body),
  appealsMetrics:()     => API.get('/v1/appeals/metrics'),
  appealGet:     (id)   => API.get(`/v1/appeals/${id}`),

  complianceFrameworks: ()        => API.get('/v1/compliance/frameworks'),
  complianceEvaluate:   (body)    => API.post('/v1/compliance/evaluate', body),
  complianceClassify:   (body)    => API.post('/v1/compliance/classify-risk', body),
  complianceFria:       (body)    => API.post('/v1/compliance/fria/generate', body),
  complianceReport:     (fw)      => API.get(`/v1/compliance/report/${fw}`),

  intelligenceIngest: (body) => API.post('/v1/intelligence/ingest', body),
  intelligenceQuery:  (body) => API.post('/v1/intelligence/query', body),
  intelligenceStats:  ()     => API.get('/v1/intelligence/stats'),
  bridgeStatus:       ()     => API.get('/v1/intelligence/bridge/status'),

  trustScore: (sid) => API.get(`/v1/trust/${sid}`),
};

// ── Utilidades de UI ──────────────────────────────────
function toast(msg, type = 'success') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.className = `toast-${type}`;
  el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 3000);
}

function fmtHash(h) {
  if (!h) return '—';
  return h.substring(0, 8) + '...' + h.substring(h.length - 6);
}

function fmtTime(ms) {
  if (ms === undefined || ms === null) return '—';
  const color = ms < 50 ? '#10b981' : ms < 150 ? '#f59e0b' : '#ef4444';
  return `<span style="color:${color};font-weight:700">${ms.toFixed(1)}ms</span>`;
}

function badgeAction(action) {
  const map = {
    ALLOW:  'badge-green',
    BLOCK:  'badge-red',
    REVIEW: 'badge-yellow',
  };
  return `<span class="badge ${map[action] || 'badge-blue'}">${action}</span>`;
}

function renderJSON(obj, el) {
  if (el) el.textContent = JSON.stringify(obj, null, 2);
}
