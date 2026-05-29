// search.js — Pesquisa global BuildToValue (Cmd+K / Ctrl+K)
// Compartilhado por todas as páginas. Usa os tokens CSS da página (--surface, --accent…).
(function () {
  // ===== DADOS (sincronizados com Fleet / Gov / Ledger) =====
  const agents = [
    { id:'med-triage-01', name:'Medical Triage',  owner:'Hospital São Paulo', bundle:'medical',   status:'online' },
    { id:'finbot-credit', name:'Credit Scoring',  owner:'BancoPay',           bundle:'financial', status:'online' },
    { id:'hr-screener',   name:'Resume Screener', owner:'TalentCorp',         bundle:'hr',        status:'online' },
    { id:'support-l1',    name:'Support Tier 1',  owner:'Acme SaaS',          bundle:'default',   status:'online' },
    { id:'legal-assist',  name:'Legal Research',  owner:'Pereira Advogados',  bundle:'legal',     status:'degraded' },
    { id:'dev-copilot',   name:'Code Review Bot', owner:'Internal Eng',       bundle:'research',  status:'online' },
    { id:'edu-tutor',     name:'Tutor Pedagógico',owner:'ColégioX',           bundle:'education', status:'online' },
    { id:'content-mod',   name:'Content Moderator',owner:'SocialApp',         bundle:'default',   status:'offline' },
  ];
  const appeals = [
    { id:'ap_8f3b21', agentId:'med-triage-01', reason:'Bloqueio de pergunta sobre histórico médico próprio', status:'pending' },
    { id:'ap_9d227e', agentId:'finbot-credit', reason:'FRIA classificada como alto risco', status:'pending' },
    { id:'ap_2b77f0', agentId:'finbot-credit', reason:'Crédito negado sem justificativa clara', status:'pending' },
    { id:'ap_3e09b1', agentId:'hr-screener',   reason:'Decisão revertida para ALLOW após contexto', status:'resolved' },
  ];
  const decisions = [
    { id:'v_block_sql',  agentId:'finbot-credit', verdict:'BLOCK',   risk:0.91, vector:'SQL injection' },
    { id:'v_allow_edu',  agentId:'med-triage-01', verdict:'ALLOW',   risk:0.22, vector:'pergunta clínica' },
    { id:'v_redact_pii', agentId:'support-l1',    verdict:'REDACT',  risk:0.62, vector:'PII · CPF' },
    { id:'v_edu_phish',  agentId:'dev-copilot',   verdict:'EDUCATE', risk:0.45, vector:'phishing hipotético' },
  ];

  const PAGES = [
    { type:'página', title:'Home', subtitle:'Landing · visão geral do BuildToValue', url:'BuildToValue Landing.html', keywords:'home landing inicio' },
    { type:'página', title:'Fleet', subtitle:'Frota de agentes governados', url:'Fleet.html', keywords:'fleet frota agentes' },
    { type:'página', title:'Lab', subtitle:'Laboratório · cenários e modo multi-agente', url:'Lab.html', keywords:'lab laboratorio cenarios multi-agente comparar' },
    { type:'página', title:'Dashboard', subtitle:'Visão executiva cross-persona', url:'Dashboard.html', keywords:'dashboard executivo kpi' },
    { type:'página', title:'Ledger Explorer', subtitle:'Registro imutável BLAKE3 + HMAC', url:'Ledger Explorer.html', keywords:'ledger blake3 hmac chain' },
    { type:'página', title:'Proxy Demo', subtitle:'Interceptação de chamadas LLM', url:'Proxy Demo.html', keywords:'proxy interceptacao llm' },
    { type:'página', title:'Sanitizer Demo', subtitle:'Detecção e redação de PII', url:'Sanitizer Demo.html', keywords:'sanitizer pii redacao cpf' },
    { type:'persona', title:'Engenharia', subtitle:'The Pulse · latência e kernel Rust', url:'Persona Eng.html', keywords:'eng engenharia latencia rust' },
    { type:'persona', title:'CISO', subtitle:'Segurança · ataques e ledger', url:'Persona CISO.html', keywords:'ciso seguranca ataques' },
    { type:'persona', title:'DPO', subtitle:'Compliance · FRIA e PII', url:'Persona DPO.html', keywords:'dpo compliance fria lgpd gdpr' },
    { type:'persona', title:'Governança', subtitle:'Contestabilidade · apelações SLA 24h', url:'Persona Gov.html', keywords:'gov governanca apelacoes contestabilidade' },
  ];

  // ===== ÍNDICE =====
  const index = [...PAGES];
  agents.forEach(a => index.push({
    type:'agente', title:a.name,
    subtitle:`${a.id} · owner ${a.owner} · bundle ${a.bundle} · ${a.status}`,
    url:'Fleet.html', keywords:`${a.name} ${a.id} ${a.owner} ${a.bundle} ${a.status}`
  }));
  appeals.forEach(ap => {
    const ag = agents.find(a => a.id === ap.agentId) || { name:'—' };
    index.push({ type:'apelação', title:`Apelação ${ap.id}`,
      subtitle:`${ag.name} · ${ap.reason} · ${ap.status}`,
      url:'Persona Gov.html', keywords:`${ap.id} ${ap.reason} ${ag.name} apelacao` });
  });
  decisions.forEach(d => {
    const ag = agents.find(a => a.id === d.agentId) || { name:'—' };
    index.push({ type:'decisão', title:`${d.verdict} · ${d.vector}`,
      subtitle:`${ag.name} · risk ${d.risk} · ${d.id}`,
      url:'Ledger Explorer.html', keywords:`${d.id} ${d.verdict} ${d.vector} ${ag.name} decisao` });
  });

  const TYPE_COLOR = {
    'página':'var(--accent-2,#79c0ff)', 'persona':'var(--accent-2,#79c0ff)',
    'agente':'var(--allow,#3fb950)', 'apelação':'var(--educate,#d29922)', 'decisão':'var(--redact,#bc8cff)'
  };

  let modal, input, resultsEl, sel = -1, current = [];

  function build() {
    modal = document.createElement('div');
    modal.id = 'gsearch';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-label', 'Pesquisa global');
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);display:none;justify-content:center;align-items:flex-start;padding-top:14vh;z-index:10000;';
    modal.innerHTML = `
      <div style="background:var(--surface,#141921);border:1px solid var(--border-strong,rgba(255,255,255,0.14));border-radius:16px;width:92%;max-width:600px;box-shadow:0 30px 80px rgba(0,0,0,0.6);overflow:hidden;font-family:var(--sans,Inter,system-ui,sans-serif)">
        <div style="padding:14px 16px;border-bottom:1px solid var(--border,rgba(255,255,255,0.07));display:flex;align-items:center;gap:10px">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--muted,#8b95a3)" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input id="gsearch-input" type="text" placeholder="Pesquisar agentes, apelações, decisões, páginas…" aria-label="Campo de busca" autocomplete="off" style="flex:1;background:transparent;border:none;color:var(--text,#e6edf3);font-size:15px;outline:none;font-family:inherit">
          <kbd style="font-family:var(--mono,monospace);font-size:10px;color:var(--muted,#8b95a3);border:1px solid var(--border,rgba(255,255,255,0.07));border-radius:5px;padding:2px 7px">esc</kbd>
        </div>
        <div id="gsearch-results" role="listbox" aria-label="Resultados da pesquisa" style="max-height:52vh;overflow-y:auto;padding:6px 0"></div>
        <div style="padding:9px 16px;border-top:1px solid var(--border,rgba(255,255,255,0.07));font-family:var(--mono,monospace);font-size:10.5px;color:var(--muted,#8b95a3);display:flex;gap:16px">
          <span>↑↓ navegar</span><span>⏎ abrir</span><span>esc fechar</span>
        </div>
      </div>`;
    document.body.appendChild(modal);
    input = modal.querySelector('#gsearch-input');
    resultsEl = modal.querySelector('#gsearch-results');

    render([]);
    input.addEventListener('input', () => {
      const t = input.value.trim().toLowerCase();
      if (t.length < 1) { render([]); return; }
      render(index.filter(i =>
        i.title.toLowerCase().includes(t) ||
        i.subtitle.toLowerCase().includes(t) ||
        i.keywords.toLowerCase().includes(t)
      ));
    });
    modal.addEventListener('keydown', onKey);
    modal.addEventListener('click', e => { if (e.target === modal) close(); });
  }

  function render(results) {
    current = results; sel = -1;
    if (!input.value.trim()) {
      resultsEl.innerHTML = `<div style="padding:18px 16px;color:var(--muted-2,#5a6470);font-size:13px;text-align:center">Digite para buscar em 11 páginas, agentes, apelações e decisões.</div>`;
      return;
    }
    if (!results.length) {
      resultsEl.innerHTML = `<div style="padding:18px 16px;color:var(--muted,#8b95a3);font-size:13px;text-align:center">Nenhum resultado.</div>`;
      return;
    }
    resultsEl.innerHTML = results.map((r, i) => `
      <div class="gsr" role="option" data-i="${i}" tabindex="-1" style="padding:10px 16px;cursor:pointer;border-left:3px solid transparent;display:flex;align-items:center;gap:12px">
        <span style="font-family:var(--mono,monospace);font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:0.06em;color:${TYPE_COLOR[r.type]||'var(--muted)'};border:1px solid currentColor;border-radius:100px;padding:2px 8px;flex-shrink:0;width:62px;text-align:center">${r.type}</span>
        <div style="min-width:0">
          <div style="font-size:13.5px;font-weight:600;color:var(--text,#e6edf3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${r.title}</div>
          <div style="font-size:11.5px;color:var(--muted,#8b95a3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${r.subtitle}</div>
        </div>
      </div>`).join('');
    resultsEl.querySelectorAll('.gsr').forEach(el => {
      el.addEventListener('click', () => go(parseInt(el.dataset.i)));
      el.addEventListener('mousemove', () => { sel = parseInt(el.dataset.i); highlight(); });
    });
  }

  function highlight() {
    resultsEl.querySelectorAll('.gsr').forEach((el, i) => {
      const on = i === sel;
      el.style.background = on ? 'var(--surface-2,#1c222c)' : '';
      el.style.borderLeftColor = on ? 'var(--accent,#388bfd)' : 'transparent';
      if (on) el.scrollIntoView({ block:'nearest' });
    });
  }

  function go(i) { if (current[i]) window.location.href = current[i].url; }

  function onKey(e) {
    if (e.key === 'Escape') { close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); if (current.length) { sel = (sel + 1) % current.length; highlight(); } }
    else if (e.key === 'ArrowUp') { e.preventDefault(); if (current.length) { sel = (sel - 1 + current.length) % current.length; highlight(); } }
    else if (e.key === 'Enter') { e.preventDefault(); if (sel >= 0) go(sel); else if (current.length === 1) go(0); }
  }

  function open() { modal.style.display = 'flex'; input.value = ''; render([]); setTimeout(() => input.focus(), 30); }
  function close() { modal.style.display = 'none'; }

  window.openGlobalSearch = open;
  window.closeGlobalSearch = close;

  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (modal) (modal.style.display === 'flex' ? close() : open());
    }
  });

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', build);
  else build();
})();
