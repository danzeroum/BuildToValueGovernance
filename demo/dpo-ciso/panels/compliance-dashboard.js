// Painel 2 — Compliance Dashboard (read-only).
// Fase 2 do plano: construído antes do Painel 1 porque não exige policy_signer.py.
//
// Em produção, este painel chamaria GET /api/decisions e GET /api/appeals.
// Aqui carrega o cenário pré-fabricado em ../scenarios/sector-health.json.
// O algoritmo Gilligan S1-S6 vem do orquestrador (governance-console.js)
// para garantir uma única fonte (ADR-072).
'use strict';

window.ComplianceDashboard = (function () {
  let host, ctx;

  async function loadData() {
    try {
      const res = await fetch('./scenarios/sector-health.json');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return await res.json();
    } catch (e) {
      // Fallback embarcado para servir o painel mesmo offline.
      return {
        metrics: { decisions_today: 1842, pending_appeals: 36, blocks_24h: 117, sla_breach: 2 },
        frameworks: ['LGPD', 'GDPR', 'EU AI Act', 'HIPAA', 'ISO 42001', 'NIST AI RMF'],
        appeals: synthesizeAppeals(),
      };
    }
  }

  function synthesizeAppeals() {
    const now = Date.now();
    const offsets = [22, 16, 9, 5, 1.2, -0.3, 14, 7, 3, 0.5];
    const agents = ['demo-clinical', 'support-bot', 'rh-screen', 'compliance-bot', 'pa-oracle'];
    const reasons = ['PHI exposure', 'Sensitive bias signal', 'PII redaction failure', 'Unverified vendor LLM', 'Threshold drift'];
    return offsets.map((h, i) => ({
      id: 'APL-' + (1000 + i),
      agent: agents[i % agents.length],
      reason: reasons[i % reasons.length],
      severity_shift: i % 3 === 0 ? 1 : 0,
      deadline: new Date(now + h * 3_600_000).toISOString(),
    }));
  }

  function gilliganTip(s) {
    const isEn = ctx.lang() === 'en';
    const tips = {
      S1: isEn ? 'S1: >18h remaining — low urgency' : 'S1: >18h restantes — baixa urgência',
      S2: isEn ? 'S2: 12–18h remaining — monitor' : 'S2: 12–18h restantes — monitorar',
      S3: isEn ? 'S3: 6–12h remaining — elevated' : 'S3: 6–12h restantes — elevado',
      S4: isEn ? 'S4: 2–6h remaining — high urgency' : 'S4: 2–6h restantes — alta urgência',
      S5: isEn ? 'S5: <2h — auto-escalation triggered!' : 'S5: <2h — escalonamento automático!',
      S6: isEn ? 'S6: Expired — SLA breached' : 'S6: Expirado — SLA violado',
    };
    return tips[s] || s;
  }

  function render() {
    host.innerHTML = `
      <div class="gov-anatomy">
        <strong>${ctx.t('anatomy_title')}:</strong> ${ctx.t('anatomy_body')}
      </div>
      <div class="gov-card">
        <h2 data-i18n="dash_title">${ctx.t('dash_title')}</h2>
        <p>${ctx.t('dash_intro')}</p>
      </div>
      <div class="gov-grid" id="metrics-grid"></div>
      <div class="gov-card" style="margin-top:1rem;">
        <h3>${ctx.t('dash_appeals_title')}</h3>
        <p class="hint" style="font-size:0.85rem;color:var(--gov-muted);">${ctx.t('dash_appeals_help')}</p>
        <table class="gov-table" id="appeals-table"></table>
      </div>
      <div class="gov-card">
        <h3>${ctx.t('dash_frameworks_title')}</h3>
        <p class="hint" style="font-size:0.85rem;color:var(--gov-muted);">${ctx.t('dash_frameworks_help')}</p>
        <div id="frameworks-list"></div>
      </div>
    `;
    loadData().then(renderData);
  }

  function renderData(d) {
    const mg = host.querySelector('#metrics-grid');
    const M = d.metrics;
    mg.innerHTML = `
      <div class="gov-metric"><div class="num">${M.decisions_today}</div><div class="label">${ctx.t('dash_metric_decisions')}</div></div>
      <div class="gov-metric"><div class="num">${M.pending_appeals}</div><div class="label">${ctx.t('dash_metric_appeals')}</div></div>
      <div class="gov-metric"><div class="num">${M.blocks_24h}</div><div class="label">${ctx.t('dash_metric_blocks')}</div></div>
      <div class="gov-metric"><div class="num" style="color:var(--gov-danger)">${M.sla_breach}</div><div class="label">${ctx.t('dash_metric_sla_breach')}</div></div>
    `;

    const t = host.querySelector('#appeals-table');
    const head = `<thead><tr>
      <th>${ctx.t('col_id')}</th>
      <th>${ctx.t('col_agent')}</th>
      <th>${ctx.t('col_reason')}</th>
      <th>${ctx.t('col_remaining')}</th>
      <th>${ctx.t('col_severity')}</th>
      <th>${ctx.t('col_scenario')}</th>
    </tr></thead>`;
    const rows = d.appeals.map((a) => {
      const s = ctx.gilliganScenario(a.deadline, a.severity_shift);
      return `<tr>
        <td><code>${a.id}</code></td>
        <td>${a.agent}</td>
        <td>${a.reason}</td>
        <td>${ctx.formatRemaining(a.deadline)}</td>
        <td>${a.severity_shift ? '+1' : '—'}</td>
        <td><span class="badge ${s.toLowerCase()}" title="${gilliganTip(s)}">${s}</span></td>
      </tr>`;
    }).join('');
    t.innerHTML = head + '<tbody>' + rows + '</tbody>';

    host.querySelector('#frameworks-list').innerHTML =
      d.frameworks.map((f) => `<span class="badge allow" style="margin:0.15rem;">${f}</span>`).join(' ');
  }

  function mount(id, context) {
    host = document.getElementById(id);
    ctx = context;
    return { render };
  }

  return { mount };
})();
