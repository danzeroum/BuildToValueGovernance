// Painel 3 — Audit Trail.
// Lista decisões com explain_decision em linguagem natural; exporta evidência
// forense com BLAKE3 + HMAC + comando btv-cli verify para auditoria fora do
// navegador (princípio do Modo Inspetor — Tutorial 03 do Portal).
'use strict';

window.AuditTrail = (function () {
  let host, ctx;

  function sampleDecisions() {
    return [
      {
        id: 'VRD-01HXYZ001', verdict: 'BLOCK', agent: 'demo-clinical', risk: 'high',
        ts: '2026-05-27T10:42:00Z',
        explain_pt: 'Detectado CPF em prompt clínico sem consentimento explícito. Política HIPAA_base aplicada (LGPD art. 6º, EU AI Act art. 5).',
        explain_en: 'CPF detected in a clinical prompt without explicit consent. HIPAA_base policy applied (LGPD art. 6, EU AI Act art. 5).',
        blake3: 'b3e2c9a8f4d1becf2110e3a6...4f9c1d0a',
        hmac: '9f1c4e8b2a73d5f0...c0e1b2a3',
      },
      {
        id: 'VRD-01HXYZ002', verdict: 'EDUCATE', agent: 'support-bot', risk: 'medium',
        ts: '2026-05-27T10:55:00Z',
        explain_pt: 'Conteúdo sensível detectado. Trust score do usuário > 0.6 e primeira ocorrência → BLOCK convertido em EDUCATE (Gilligan).',
        explain_en: 'Sensitive content detected. User trust score > 0.6 and first occurrence → BLOCK converted to EDUCATE (Gilligan).',
        blake3: 'a1b2c3d4e5f6...0ff1e2d3',
        hmac: '4e5f6a7b...8c9d0e1f',
      },
      {
        id: 'VRD-01HXYZ003', verdict: 'ALLOW', agent: 'rh-screen', risk: 'low',
        ts: '2026-05-27T11:10:00Z',
        explain_pt: 'Prompt limpo, sem PII detectado. Pipeline ético completo (Rawls→Levinas→Jonas→Gilligan) aprovou.',
        explain_en: 'Clean prompt, no PII detected. Full ethical pipeline (Rawls→Levinas→Jonas→Gilligan) approved.',
        blake3: 'deadbeef1234...cafe5678',
        hmac: '00112233...44556677',
      },
      {
        id: 'VRD-01HXYZ004', verdict: 'REDACT', agent: 'compliance-bot', risk: 'medium',
        ts: '2026-05-27T11:32:00Z',
        explain_pt: 'Email exposto no output do LLM. Sanitizado conforme data/policies/security/. Resposta entregue com [EMAIL] redacted.',
        explain_en: 'Email leaked in LLM output. Sanitized per data/policies/security/. Response delivered with [EMAIL] redacted.',
        blake3: 'fedcba98...76543210',
        hmac: 'aabbccdd...eeff0011',
      },
    ];
  }

  function render() {
    host.innerHTML = `
      <div class="gov-card">
        <h2>${ctx.t('audit_title')}</h2>
        <p>${ctx.t('audit_intro')}</p>
        <div style="display:flex; gap:1rem; flex-wrap:wrap; margin-top:1rem;">
          <div class="form-row" style="flex:1; min-width:140px;"><label>${ctx.t('audit_filter_risk')}</label>
            <select id="filter-risk"><option value="">—</option><option>low</option><option>medium</option><option>high</option></select>
          </div>
          <div class="form-row" style="flex:1; min-width:140px;"><label>${ctx.t('audit_filter_verdict')}</label>
            <select id="filter-verdict"><option value="">—</option><option>ALLOW</option><option>BLOCK</option><option>EDUCATE</option><option>REDACT</option></select>
          </div>
          <div class="form-row" style="flex:1; min-width:140px;"><label>${ctx.t('audit_filter_agent')}</label>
            <input id="filter-agent" placeholder="demo-clinical">
          </div>
        </div>
      </div>
      <div id="audit-list"></div>
    `;
    renderList();
    host.querySelector('#filter-risk').addEventListener('change', renderList);
    host.querySelector('#filter-verdict').addEventListener('change', renderList);
    host.querySelector('#filter-agent').addEventListener('input', renderList);
  }

  function renderList() {
    const fr = host.querySelector('#filter-risk').value;
    const fv = host.querySelector('#filter-verdict').value;
    const fa = (host.querySelector('#filter-agent').value || '').toLowerCase();
    const lang = ctx.lang();
    const list = sampleDecisions().filter((d) =>
      (!fr || d.risk === fr) && (!fv || d.verdict === fv) && (!fa || d.agent.toLowerCase().includes(fa))
    );
    host.querySelector('#audit-list').innerHTML = list.map((d) => `
      <div class="gov-card">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <span class="badge ${d.verdict.toLowerCase()}">${d.verdict}</span>
            <code style="margin-left:0.5rem;">${d.id}</code>
            <span style="color:var(--gov-muted); margin-left:0.5rem;">${d.agent} · ${new Date(d.ts).toLocaleString()}</span>
          </div>
          <button class="gov-btn secondary" data-export="${d.id}">${ctx.t('audit_export')}</button>
        </div>
        <p style="margin-top:0.75rem;"><strong>${ctx.t('audit_explain')}:</strong> ${lang === 'en' ? d.explain_en : d.explain_pt}</p>
        <details>
          <summary style="cursor:pointer; color:var(--gov-muted);">${ctx.t('audit_hash')} · ${ctx.t('audit_hmac')}</summary>
          <pre>${ctx.t('audit_hash')}: ${d.blake3}
${ctx.t('audit_hmac')}: ${d.hmac}

${ctx.t('audit_verify_hint')}
  cargo run -p btv-cli -- verify --hash ${d.blake3.slice(0, 16)}... --signature ${d.hmac.slice(0, 16)}...</pre>
        </details>
      </div>
    `).join('');

    host.querySelectorAll('[data-export]').forEach((b) => {
      b.addEventListener('click', () => exportForensic(sampleDecisions().find((d) => d.id === b.dataset.export), lang));
    });
  }

  function exportForensic(d, lang) {
    // Em produção, isto chama python/buildtovalue/compliance/document_exporter.py
    // via API. Aqui geramos um text/plain didático que pode ser impresso como PDF.
    const head = lang === 'en' ? 'BuildToValue — Forensic Evidence Export' : 'BuildToValue — Exportação de Evidência Forense';
    const sec1 = lang === 'en' ? 'Section 1 — Executive Summary' : 'Seção 1 — Resumo Executivo';
    const sec2 = lang === 'en' ? 'Section 2 — Forensic Evidence' : 'Seção 2 — Evidência Forense';
    const verifyLabel = lang === 'en' ? 'Out-of-browser verification command:' : 'Comando de verificação fora do navegador:';
    const body = [
      `# ${head}`,
      `Verdict: ${d.id}`,
      `Generated: ${new Date().toISOString()}`,
      ``,
      `## ${sec1}`,
      lang === 'en' ? d.explain_en : d.explain_pt,
      ``,
      `## ${sec2}`,
      `BLAKE3: ${d.blake3}`,
      `HMAC-SHA256: ${d.hmac}`,
      ``,
      `${verifyLabel}`,
      `  cargo run -p btv-cli -- verify --hash ${d.blake3} --signature ${d.hmac}`,
      ``,
      `[SIMULATION — LEDGER NOT AFFECTED]`,
    ].join('\n');
    const blob = new Blob([body], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${d.id}-forensic.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function mount(id, context) {
    host = document.getElementById(id);
    ctx = context;
    return { render };
  }

  return { mount };
})();
