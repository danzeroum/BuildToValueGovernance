/**
 * BuildToValue — Session Manager (localStorage)
 * Persists verdicts, trust history, appeals, and preferences across pages.
 */

const Session = (() => {
  const KEY = 'btv_session_v2';
  const MAX_HISTORY = 100;
  const TTL_MS = 24 * 60 * 60 * 1000;

  function _load() {
    try {
      return JSON.parse(localStorage.getItem(KEY) || 'null') || _empty();
    } catch { return _empty(); }
  }

  function _save(data) {
    try { localStorage.setItem(KEY, JSON.stringify(data)); } catch {}
  }

  function _empty() {
    return {
      session_id: _uuid(),
      created_at: Date.now(),
      verdict_history: [],
      trust_score_history: [],
      appeal_history: [],
      preferences: { persona: 'all', deepseekEnabled: true, theme: 'dark', offlineMode: false },
    };
  }

  function _uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  function _cleanup(data) {
    const cutoff = Date.now() - TTL_MS;
    data.verdict_history     = data.verdict_history.filter(v => v.ts > cutoff);
    data.trust_score_history = data.trust_score_history.filter(v => v.ts > cutoff);
    data.appeal_history      = data.appeal_history.filter(v => v.ts > cutoff);
    return data;
  }

  let _data = _cleanup(_load());

  return {
    get sessionId() { return _data.session_id; },

    // Verdicts
    addVerdict(verdict) {
      _data.verdict_history.unshift({ ...verdict, ts: Date.now() });
      if (_data.verdict_history.length > MAX_HISTORY) {
        _data.verdict_history = _data.verdict_history.slice(0, MAX_HISTORY);
      }
      if (verdict.trust_score !== undefined) {
        _data.trust_score_history.push({
          ts: Date.now(),
          value: verdict.trust_score,
          action: verdict.action,
          n: _data.trust_score_history.length + 1,
        });
        if (_data.trust_score_history.length > 200) {
          _data.trust_score_history = _data.trust_score_history.slice(-200);
        }
      }
      _save(_data);
    },

    getHistory(limit = 50) {
      return _data.verdict_history.slice(0, limit);
    },

    getTrustHistory() {
      return _data.trust_score_history;
    },

    getStats() {
      const h = _data.verdict_history;
      if (!h.length) return { total: 0, blockRate: 0, avgLatency: 0, avgRisk: 0 };
      const blocked = h.filter(v => v.action === 'BLOCK' || v.action === 'REFUSE').length;
      const latencies = h.map(v => v.latency_ms).filter(Boolean);
      const risks = h.map(v => v.adjusted_risk).filter(v => v !== undefined);
      return {
        total: h.length,
        blockRate: blocked / h.length,
        avgLatency: latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0,
        avgRisk: risks.length ? risks.reduce((a, b) => a + b, 0) / risks.length : 0,
        lastTrust: h[0]?.trust_score,
      };
    },

    // Appeals
    addAppeal(appeal) {
      _data.appeal_history.unshift({ ...appeal, ts: Date.now() });
      _save(_data);
    },

    getAppeals() { return _data.appeal_history; },

    // Preferences
    getPrefs() { return { ..._data.preferences }; },
    setPref(key, value) {
      _data.preferences[key] = value;
      _save(_data);
    },
    getTheme() { return _data.preferences.theme || 'dark'; },
    setTheme(t) { this.setPref('theme', t); document.documentElement.setAttribute('data-theme', t); },
    isDeepSeekEnabled() { return _data.preferences.deepseekEnabled !== false; },
    toggleDeepSeek() {
      const val = !this.isDeepSeekEnabled();
      this.setPref('deepseekEnabled', val);
      return val;
    },

    // Reset
    clear() {
      const prefs = _data.preferences;
      _data = _empty();
      _data.preferences = prefs;
      _save(_data);
    },

    init() {
      document.documentElement.setAttribute('data-theme', _data.preferences.theme || 'dark');
      return this;
    },

    export() {
      return JSON.stringify(_data, null, 2);
    },
  };
})();
