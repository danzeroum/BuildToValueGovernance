/**
 * BuildToValue Trust OS — API client
 * All calls go through /api/* proxy (no key exposure)
 */

const API = {
  base: '/api',
  timeout: 5000,

  async _call(method, path, body, opts = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeout || this.timeout);

    const fetchOpts = {
      method,
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
    };
    if (body) fetchOpts.body = JSON.stringify(body);

    try {
      const res = await fetch(this.base + path, fetchOpts);
      clearTimeout(timer);
      let data;
      try { data = await res.json(); } catch { data = {}; }
      return { status: res.status, ok: res.ok, data };
    } catch (err) {
      clearTimeout(timer);
      if (err.name === 'AbortError') throw new Error('timeout');
      throw err;
    }
  },

  async _callWithRetry(method, path, body, maxRetries = 2) {
    let delay = 500;
    for (let i = 0; i <= maxRetries; i++) {
      try {
        return await this._call(method, path, body);
      } catch (err) {
        if (i === maxRetries) throw err;
        await new Promise(r => setTimeout(r, delay));
        delay *= 2;
      }
    }
  },

  get:  (path, opts)      => API._call('GET',  path, null, opts),
  post: (path, body, opts) => API._call('POST', path, body, opts),

  // ── Health ────────────────────────────────────
  health: () => API.get('/health'),

  // ── Core decisions ───────────────────────────
  decide:     (body) => API.post('/v1/decide', body),
  validate:   (body) => API.post('/v1/validate', body),
  sanitize:   (body) => API.post('/v1/sanitize', body),
  agentDecide:(body) => API.post('/v1/agent/decide', body),

  // ── Trust ────────────────────────────────────
  trustScore: (sid)  => API.get(`/v1/trust/${sid}`),

  // ── Proxy LLM ────────────────────────────────
  proxyDecide: (body) => API.post('/v1/proxy/decide', body, { timeout: 30000 }),

  // ── Ledger ───────────────────────────────────
  ledgerQuery: (params) => API.get('/v1/ledger/query' + (params ? '?' + new URLSearchParams(params) : '')),
  ledgerStats: ()        => API.get('/v1/ledger/stats'),

  // ── Appeals ──────────────────────────────────
  appealsList:    ()     => API.get('/v1/appeals'),
  appealsCreate:  (body) => API.post('/v1/appeals', body),
  appealsMetrics: ()     => API.get('/v1/appeals/metrics'),
  appealGet:      (id)   => API.get(`/v1/appeals/${id}`),

  // ── Compliance ───────────────────────────────
  complianceFrameworks: ()     => API.get('/v1/compliance/frameworks'),
  complianceEvaluate:   (body) => API.post('/v1/compliance/evaluate', body),
  complianceClassify:   (body) => API.post('/v1/compliance/classify-risk', body),
  complianceFria:       (body) => API.post('/v1/compliance/fria/generate', body, { timeout: 20000 }),
  complianceReport:     (fw)   => API.get(`/v1/compliance/report/${fw}`),

  // ── Intelligence ─────────────────────────────
  intelligenceIngest: (body) => API.post('/v1/intelligence/ingest', body),
  intelligenceQuery:  (body) => API.post('/v1/intelligence/query', body),
  intelligenceStats:  ()     => API.get('/v1/intelligence/stats'),
  intelligenceThreats:()     => API.get('/v1/intelligence/threats'),
  bridgeStatus:       ()     => API.get('/v1/intelligence/bridge/status'),
};

// ── Offline mode detection ────────────────────────────────
const OfflineMode = {
  enabled: false,
  _check: null,

  enable() {
    this.enabled = true;
    document.querySelectorAll('.offline-badge').forEach(el => el.classList.add('visible'));
    console.info('[BTV] Offline mode active — using mock data');
  },
  disable() {
    this.enabled = false;
    document.querySelectorAll('.offline-badge').forEach(el => el.classList.remove('visible'));
  },

  async autoDetect() {
    try {
      const r = await API.health();
      if (r.ok) { this.disable(); return true; }
      this.enable(); return false;
    } catch {
      this.enable(); return false;
    }
  },
};

// ── UI Utilities ──────────────────────────────────────────
function toast(msg, type = 'success', duration = 3500) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.className = `toast-${type}`;
  el.style.display = 'block';
  clearTimeout(el._timer);
  el._timer = setTimeout(() => { el.style.display = 'none'; }, duration);
}

function fmtHash(h) {
  if (!h) return '—';
  return h.length > 16
    ? h.substring(0, 8) + '…' + h.substring(h.length - 6)
    : h;
}

function fmtTime(ms) {
  if (ms === undefined || ms === null) return '—';
  const num = typeof ms === 'number' ? ms : parseFloat(ms);
  if (isNaN(num)) return '—';
  const color = num < 50 ? 'var(--allow)' : num < 150 ? 'var(--educate)' : 'var(--block)';
  return `<span style="color:${color};font-weight:700;font-family:var(--mono)">${num.toFixed(1)}ms</span>`;
}

function fmtRisk(v) {
  if (v === undefined || v === null) return '—';
  const n = parseFloat(v);
  const color = n < 0.3 ? 'var(--allow)' : n < 0.7 ? 'var(--educate)' : 'var(--block)';
  return `<span style="color:${color};font-weight:700;font-family:var(--mono)">${n.toFixed(3)}</span>`;
}

function badgeAction(action) {
  const cls = {
    ALLOW: 'badge-allow', BLOCK: 'badge-block', EDUCATE: 'badge-educate',
    LOG: 'badge-log', REDACT: 'badge-redact', INSPECT: 'badge-inspect',
    REPORT: 'badge-report', REFUSE: 'badge-refuse', REVIEW: 'badge-yellow',
  };
  const emo = {
    ALLOW: '✓', BLOCK: '✕', EDUCATE: '⚑', LOG: '◎', REDACT: '◈',
    INSPECT: '◉', REPORT: '◆', REFUSE: '⊘', REVIEW: '⚠',
  };
  const c = cls[action] || 'badge-muted';
  const e = emo[action] || '?';
  return `<span class="badge ${c}">${e} ${action}</span>`;
}

function actionColor(action) {
  const map = {
    ALLOW: 'var(--allow)', BLOCK: 'var(--block)', EDUCATE: 'var(--educate)',
    LOG: 'var(--log)', REDACT: 'var(--redact)', INSPECT: 'var(--inspect)',
    REPORT: 'var(--report)', REFUSE: 'var(--refuse)', REVIEW: 'var(--yellow)',
  };
  return map[action] || 'var(--muted)';
}

function renderJSON(obj, el) {
  if (el) el.textContent = JSON.stringify(obj, null, 2);
}

function copyToClipboard(text, label = 'Copiado!') {
  navigator.clipboard.writeText(text).then(
    () => toast(label, 'success'),
    () => toast('Falha ao copiar', 'error')
  );
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString('pt-BR'); } catch { return ts; }
}

function pct(v) { return ((v || 0) * 100).toFixed(0) + '%'; }
