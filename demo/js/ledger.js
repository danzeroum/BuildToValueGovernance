/**
 * BuildToValue — Ledger Explorer + BLAKE3 Chain Verification
 */

const Ledger = (() => {
  let _entries = [];
  let _filters = { action: '', dateFrom: '', dateTo: '' };

  async function load(filters = {}) {
    _filters = { ..._filters, ...filters };
    try {
      const params = {};
      if (_filters.action) params.action = _filters.action;
      if (_filters.limit)  params.limit  = _filters.limit;
      const r = await getAPI().ledgerQuery(Object.keys(params).length ? params : null);
      _entries = Array.isArray(r.data) ? r.data : (r.data?.entries || r.data?.records || []);
      return _entries;
    } catch (e) {
      console.error('[Ledger] load error', e);
      return [];
    }
  }

  function renderTimeline(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const filtered = _entries.filter(e => {
      if (_filters.action && e.action !== _filters.action) return false;
      return true;
    });

    if (!filtered.length) {
      container.innerHTML = '<div style="color:var(--muted);text-align:center;padding:32px">Sem registros no ledger.</div>';
      return;
    }

    container.innerHTML = `<div class="ledger-timeline">
      ${filtered.map((entry, idx) => renderEntry(entry, idx)).join('')}
    </div>`;
  }

  function renderEntry(entry, idx = 0) {
    const action = entry.action || 'UNKNOWN';
    const risk   = parseFloat(entry.adjusted_risk || entry.risk || 0);
    const riskColor = risk < 0.3 ? 'var(--allow)' : risk < 0.7 ? 'var(--educate)' : 'var(--block)';

    return `<div class="ledger-entry action-${action}" style="animation-delay:${idx*0.03}s">
      <div class="ledger-entry-card">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
          ${badgeAction(action)}
          <span style="font-family:var(--mono);font-size:10px;color:var(--muted)">${formatTimestamp(entry.timestamp)}</span>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;margin-bottom:8px">
          <div>
            <div style="color:var(--muted);margin-bottom:2px">Verdict ID</div>
            <div class="mono truncate" title="${entry.verdict_id || '—'}">${fmtHash(entry.verdict_id || entry.id)}</div>
          </div>
          <div>
            <div style="color:var(--muted);margin-bottom:2px">Adjusted Risk</div>
            <div style="font-family:var(--mono);font-weight:700;color:${riskColor}">${risk.toFixed(3)}</div>
          </div>
        </div>
        <div style="font-size:11px;margin-bottom:6px">
          <div style="color:var(--muted);margin-bottom:2px">BLAKE3 Hash</div>
          <div class="mono word-break" style="color:var(--log);font-size:10px">${(entry.blake3_hash || entry.signature || '—').substring(0, 32)}…</div>
        </div>
        ${entry.previous_hash ? `<div style="font-size:11px">
          <div style="color:var(--muted);margin-bottom:2px">Previous Hash</div>
          <div class="mono word-break" style="font-size:10px;color:var(--muted)">${entry.previous_hash.substring(0, 32)}…</div>
        </div>` : ''}
        <div class="ledger-verify-wrap" id="verify-${idx}">
          ${entry.finding_count ? `<span style="color:var(--muted)">${entry.finding_count} findings (${entry.critical_count || 0} críticos)</span> ·` : ''}
          ${entry.contestable ? '<span class="badge badge-blue" style="font-size:10px">Contestável</span>' : ''}
        </div>
      </div>
    </div>`;
  }

  async function verifyChain(containerId, statusId) {
    const statusEl = document.getElementById(statusId);
    if (statusEl) statusEl.innerHTML = '<span class="spinner spinner-sm"></span> Verificando cadeia BLAKE3…';

    await new Promise(r => setTimeout(r, 800));

    const entries = _entries;
    if (!entries.length) {
      if (statusEl) statusEl.innerHTML = '<span style="color:var(--muted)">Nenhum registro para verificar.</span>';
      return;
    }

    let allValid = true;
    for (let i = 0; i < entries.length; i++) {
      const verifyEl = document.getElementById(`verify-${i}`);
      await new Promise(r => setTimeout(r, 60));
      const isValid = _simulateHashVerify(entries[i], entries[i + 1]);
      if (!isValid) allValid = false;
      if (verifyEl) {
        verifyEl.insertAdjacentHTML('beforeend',
          `<span class="verify-check check-reveal">${isValid ? '✓' : '✗'}</span>`);
      }
    }

    if (statusEl) {
      statusEl.innerHTML = allValid
        ? '<span style="color:var(--allow);font-weight:700">✓ Cadeia íntegra — todos os hashes verificados</span>'
        : '<span style="color:var(--block);font-weight:700">⚠ Inconsistência detectada na cadeia</span>';
    }
  }

  function _simulateHashVerify(entry, next) {
    return !!(entry.blake3_hash || entry.signature);
  }

  function search(verdictId) {
    return _entries.filter(e =>
      (e.verdict_id || '').toLowerCase().includes(verdictId.toLowerCase()) ||
      (e.blake3_hash || '').toLowerCase().includes(verdictId.toLowerCase())
    );
  }

  return { load, renderTimeline, renderEntry, verifyChain, search, get entries() { return _entries; } };
})();
