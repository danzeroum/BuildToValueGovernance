// Painel 1 — Policy Editor Visual.
//
// PRINCÍPIO INVIOLÁVEL: este painel NUNCA toca o runtime.
// O fluxo obrigatório está documentado no campo "editor_flow" do i18n:
//   1. Validação client-side contra ./schemas/policy.schema.json
//   2. validate_policy_schema.py (server-side, CI)
//   3. policy_signer.py → Ed25519 da Ethics Committee (ADR-064)
//   4. PR em data/policies/ → CI (alignment_regression + policy-blind-test)
//   5. Merge manual → reload assinado pelo kernel
//
// Se o usuário tentar pular qualquer passo, a UI bloqueia.
'use strict';

window.PolicyEditor = (function () {
  let host, ctx;

  function render() {
    host.innerHTML = `
      <div class="gov-card">
        <h2>${ctx.t('editor_title')}</h2>
        <p>${ctx.t('editor_intro')}</p>
        <div class="flow-warning">
          <strong>${ctx.t('editor_flow')}</strong>
          <ol style="margin: 0.5rem 0 0 1.25rem;">
            <li>${ctx.t('editor_step1')}</li>
            <li>${ctx.t('editor_step2')}</li>
            <li>${ctx.t('editor_step3')}</li>
            <li>${ctx.t('editor_step4')}</li>
            <li>${ctx.t('editor_step5')}</li>
          </ol>
          <p style="margin: 0.5rem 0 0; color: var(--gov-danger); font-weight: 600;">
            ${ctx.t('editor_warning')}
          </p>
        </div>
      </div>

      <div class="gov-card">
        <form id="policy-form">
          <div class="form-row">
            <label>${ctx.t('editor_sector')}</label>
            <select name="sector">
              <option value="healthcare">healthcare</option>
              <option value="fintech">fintech</option>
              <option value="education">education</option>
              <option value="aerospace">aerospace</option>
              <option value="government">government</option>
            </select>
          </div>
          <div class="form-row">
            <label>${ctx.t('editor_threshold')} (0.50 – 0.85)</label>
            <input type="number" name="threshold" min="0.50" max="0.85" step="0.01" value="0.65">
          </div>
          <div class="form-row">
            <label>${ctx.t('editor_hard_block')}</label>
            <textarea name="hard_block" rows="2" placeholder="exposure of patient data&#10;sql injection">exposure of patient data</textarea>
          </div>
          <div class="form-row">
            <label>${ctx.t('editor_jurisdiction')}</label>
            <input name="jurisdiction" value="BR,EU">
            <div class="hint">${ctx.t('editor_jur_hint')}</div>
          </div>
          <div class="form-row">
            <label>${ctx.t('editor_bias')} *</label>
            <textarea name="biases" rows="2" required placeholder="Sample bias toward English-language records">Sample bias toward English-language records</textarea>
            <div class="hint">${ctx.t('editor_bias_hint')}</div>
          </div>
          <div class="form-row">
            <label>${ctx.t('editor_mitigations')}</label>
            <textarea name="mitigations" rows="2">Force PT/EN dual-translation review before merge</textarea>
          </div>
          <div style="display:flex; gap:0.5rem;">
            <button type="button" class="gov-btn" id="btn-review">${ctx.t('editor_review')}</button>
            <button type="button" class="gov-btn secondary" id="btn-validate">${ctx.t('editor_validate')}</button>
            <button type="button" class="gov-btn secondary" id="btn-sign">${ctx.t('editor_sign')}</button>
          </div>
        </form>
        <details class="yaml-preview" id="yaml-block" style="display:none;">
          <summary>${ctx.t('editor_yaml')}</summary>
          <pre id="yaml-out"></pre>
        </details>
        <div id="validation-result" style="margin-top:0.75rem;"></div>
      </div>
    `;

    host.querySelector('#btn-review').addEventListener('click', () => { renderYaml(); });
    host.querySelector('#btn-validate').addEventListener('click', validateSchema);
    host.querySelector('#btn-sign').addEventListener('click', computeLocalHmac);
  }

  function readForm() {
    const f = host.querySelector('#policy-form');
    const fd = new FormData(f);
    return {
      version: '1.0',
      schema_type: 'policy-rules',
      metadata: {
        name: `BTV Governance Console — ${fd.get('sector')}`,
        author: 'governance-console-ui',
        created_at: new Date().toISOString().slice(0, 10),
      },
      jurisdiction: fd.get('jurisdiction'),
      bias_declaration: {
        known_biases: String(fd.get('biases') || '').split('\n').map((s) => s.trim()).filter(Boolean),
        mitigations: String(fd.get('mitigations') || '').split('\n').map((s) => s.trim()).filter(Boolean),
        review_date: new Date().toISOString().slice(0, 10),
      },
      thresholds: {
        report_threshold: parseFloat(fd.get('threshold')),
        hard_block_terms: String(fd.get('hard_block') || '').split('\n').map((s) => s.trim()).filter(Boolean),
      },
    };
  }

  function toYaml(obj, indent = 0) {
    const pad = '  '.repeat(indent);
    if (Array.isArray(obj)) {
      if (!obj.length) return '[]';
      return '\n' + obj.map((v) => `${pad}- ${typeof v === 'object' ? toYaml(v, indent + 1).trimStart() : v}`).join('\n');
    }
    if (obj && typeof obj === 'object') {
      return Object.entries(obj).map(([k, v]) => {
        if (Array.isArray(v) || (v && typeof v === 'object')) {
          return `${pad}${k}:${toYaml(v, indent + 1)}`;
        }
        return `${pad}${k}: ${typeof v === 'string' && v.includes(':') ? JSON.stringify(v) : v}`;
      }).join('\n');
    }
    return String(obj);
  }

  function renderYaml() {
    const obj = readForm();
    host.querySelector('#yaml-block').style.display = 'block';
    host.querySelector('#yaml-block').open = true;
    host.querySelector('#yaml-out').textContent = toYaml(obj);
  }

  function setResult(html, ok) {
    const el = host.querySelector('#validation-result');
    el.innerHTML = `<div class="gov-card" style="border-left:4px solid ${ok ? 'var(--gov-ok)' : 'var(--gov-danger)'};">${html}</div>`;
  }

  function validateSchema() {
    renderYaml();
    const obj = readForm();
    const errors = [];
    if (!obj.metadata || !obj.metadata.name) errors.push('metadata.name required');
    if (!/^[A-Z]{2}(,[A-Z]{2})*$/.test(String(obj.jurisdiction || ''))) errors.push('jurisdiction must match ^[A-Z]{2}(,[A-Z]{2})*$');
    if (!obj.bias_declaration.known_biases.length) errors.push('bias_declaration.known_biases required (Rawls blind-test invariant)');
    const t = obj.thresholds.report_threshold;
    if (!(t >= 0.5 && t <= 0.85)) errors.push('thresholds.report_threshold must be in [0.50, 0.85]');
    if (errors.length === 0) {
      setResult(`<strong>✓</strong> ${ctx.t('validation_ok')}`, true);
    } else {
      setResult(`<strong>✗</strong> ${ctx.t('validation_fail')}<ul>${errors.map((e) => `<li>${e}</li>`).join('')}</ul>`, false);
    }
  }

  async function computeLocalHmac() {
    renderYaml();
    const yamlText = host.querySelector('#yaml-out').textContent;
    const enc = new TextEncoder();
    const key = enc.encode('btv-local-demo-key'); // local-only; ADR-064 Ed25519 acontece em scripts/policy_signer.py
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(yamlText));
    const hex = Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
    setResult(`<strong>${ctx.t('sig_ok')}</strong><br><code style="word-break:break-all;">HMAC-SHA256: ${hex}</code>`, true);
  }

  function mount(id, context) {
    host = document.getElementById(id);
    ctx = context;
    return { render };
  }

  return { mount };
})();
