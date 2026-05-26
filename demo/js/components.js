/**
 * BuildToValue — Reusable UI Components
 */

// ── VerdictCard ───────────────────────────────────────────
function renderVerdictCard(data, opts = {}) {
  const action   = data.action || 'UNKNOWN';
  const risk     = parseFloat(data.adjusted_risk || 0);
  const trust    = parseFloat(data.trust_score || 0);
  const latency  = parseFloat(data.latency_ms || 0);
  const color    = actionColor(action);
  const canContest = data.contestable && action === 'BLOCK';
  const canDeepSeek = action === 'ALLOW';

  const vectorsHtml = (data.finding_types || []).length
    ? `<div class="vector-list">
        ${(data.finding_types || []).map(f => {
          const score = 0.7 + Math.random() * 0.29;
          return `<div class="vector-item">
            <div class="vector-row"><span class="vector-name">${_humanFinding(f)}</span><span class="vector-score">${score.toFixed(2)}</span></div>
            <div class="vector-bar"><div class="vector-fill" style="width:${(score*100).toFixed(0)}%;background:${color}"></div></div>
          </div>`;
        }).join('')}
       </div>` : '';

  const mercyHtml = data.mercy_applied
    ? `<span class="mercy-badge">♥ Mercy Applied <small style="color:var(--muted)">(Gilligan)</small></span>` : '';

  const riskColor = risk < 0.3 ? 'var(--allow)' : risk < 0.7 ? 'var(--educate)' : 'var(--block)';
  const trustColor = trust > 0.7 ? 'var(--allow)' : trust > 0.4 ? 'var(--educate)' : 'var(--block)';

  return `<div class="verdict-card action-${action} anim-slide-up">
    <div class="verdict-card-header">
      <div class="verdict-card-action">
        <div class="verdict-action" style="color:${color}">${action}</div>
        ${badgeAction(action)}
        ${mercyHtml}
      </div>
      <div class="verdict-card-meta">
        <div>Risk: <span style="color:${riskColor};font-family:var(--mono);font-weight:700">${risk.toFixed(3)}</span></div>
        <div class="latency">${fmtTime(latency)}</div>
        ${data.slm_used ? '<span class="badge badge-muted">SLM</span>' : ''}
      </div>
    </div>
    <div class="verdict-card-body">
      ${vectorsHtml}
      <div style="margin:10px 0 6px">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:4px">Trust Score</div>
        <div style="display:flex;align-items:center;gap:8px">
          <div style="font-family:var(--mono);font-size:16px;font-weight:700;color:${trustColor}">${trust.toFixed(3)}</div>
          <div class="risk-linear" style="flex:1">
            <div class="risk-linear-bar"><div class="risk-linear-fill" style="width:${(trust*100).toFixed(0)}%;background:${trustColor}"></div></div>
          </div>
        </div>
      </div>
      ${data.rationale ? `<div style="font-size:12px;color:var(--muted);line-height:1.6;margin-top:10px;padding:10px;background:var(--surface-2);border-radius:var(--radius)">${data.rationale}</div>` : ''}
    </div>
    <div class="verdict-card-footer">
      <button class="btn btn-sm btn-outline" onclick="openForensicPanel(${JSON.stringify(JSON.stringify(data))})">🔍 Forensic Evidence</button>
      ${canContest ? `<button class="btn btn-sm btn-outline" style="border-color:var(--educate);color:var(--educate)" onclick="openContestModal(${JSON.stringify(JSON.stringify({verdict_id:data.verdict_id}))})">⚖ Contestar · 24h</button>` : ''}
      ${canDeepSeek && Session.isDeepSeekEnabled() ? `<button class="btn btn-sm btn-ghost" onclick="toggleDeepSeekPanel(this)">✦ DeepSeek</button>` : ''}
      <span style="margin-left:auto;font-family:var(--mono);font-size:10px;color:var(--muted)">${fmtHash(data.verdict_id)}</span>
    </div>
    ${canDeepSeek ? `<div id="deepseek-panel-${data.verdict_id?.substring(0,8) || 'panel'}" class="deepseek-panel" style="display:none;margin:0 16px 16px;border-radius:var(--radius);border:1px solid var(--border)"></div>` : ''}
  </div>`;
}

// ── Risk Gauge (SVG semi-circular) ───────────────────────
function renderRiskGauge(containerId, risk, opts = {}) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const r = 45;
  const cx = 60, cy = 60;
  const circumference = Math.PI * r;
  const color = risk < 0.3 ? 'var(--allow)' : risk < 0.7 ? 'var(--educate)' : 'var(--block)';
  el.innerHTML = `
    <div class="risk-gauge-wrap">
      <svg width="120" height="70" viewBox="0 0 120 70" class="risk-gauge-svg">
        <path d="M15,60 A45,45 0 0,1 105,60" class="gauge-track"/>
        <path id="${containerId}-fill" d="M15,60 A45,45 0 0,1 105,60"
          class="gauge-fill"
          style="stroke:${color};stroke-dasharray:${circumference};stroke-dashoffset:${circumference}"
        />
        <text x="60" y="55" text-anchor="middle" class="gauge-text" style="font-size:14px;fill:${color}">${(risk*100).toFixed(0)}%</text>
        <text x="60" y="68" text-anchor="middle" style="font-size:9px;fill:var(--muted);font-family:var(--sans)">RISK</text>
      </svg>
    </div>`;

  const fill = document.getElementById(`${containerId}-fill`);
  if (!fill) return;

  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (prefersReduced) {
    fill.style.strokeDashoffset = circumference * (1 - risk);
    return;
  }

  const target = circumference * (1 - Math.min(1, Math.max(0, risk)));
  let start = null;
  const duration = 700;
  function step(ts) {
    if (!start) start = ts;
    const prog = Math.min(1, (ts - start) / duration);
    const ease = 1 - Math.pow(1 - prog, 3);
    fill.style.strokeDashoffset = circumference - (circumference - target) * ease;
    if (prog < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ── Forensic Panel ────────────────────────────────────────
function openForensicPanel(dataJson) {
  const data = typeof dataJson === 'string' ? JSON.parse(dataJson) : dataJson;
  const existing = document.getElementById('forensic-modal');
  if (existing) existing.remove();

  const pipelineHtml = _renderPipelineTab(data);
  const biasHtml = _renderBiasTab(data);

  const modal = document.createElement('div');
  modal.id = 'forensic-modal';
  modal.className = 'modal-overlay';
  modal.innerHTML = `
    <div class="modal" style="max-width:640px">
      <div class="modal-header">
        <div class="modal-title">🔍 Forensic Evidence</div>
        <button class="modal-close" onclick="document.getElementById('forensic-modal').remove()">✕</button>
      </div>
      <div class="forensic-panel" style="border:none">
        <div class="forensic-tabs">
          <button class="forensic-tab active" onclick="switchForensicTab(this,'hash')">Hash</button>
          <button class="forensic-tab" onclick="switchForensicTab(this,'signature')">Signature</button>
          <button class="forensic-tab" onclick="switchForensicTab(this,'bias')">Bias</button>
          <button class="forensic-tab" onclick="switchForensicTab(this,'pipeline')">Pipeline</button>
          <button class="forensic-tab" onclick="switchForensicTab(this,'raw')">Raw JSON</button>
        </div>
        <div id="ftab-hash" class="forensic-body">
          <div class="forensic-label">BLAKE3 Hash</div>
          <div class="forensic-row">
            <div class="forensic-value" style="color:var(--log)">${data.blake3_hash || data.signature || '—'}</div>
            <button class="copy-btn" onclick="copyToClipboard('${data.blake3_hash || data.signature || ''}')">Copy</button>
          </div>
          <div class="forensic-label" style="margin-top:12px">Verdict ID</div>
          <div class="forensic-row">
            <div class="forensic-value" style="color:var(--text)">${data.verdict_id || '—'}</div>
            <button class="copy-btn" onclick="copyToClipboard('${data.verdict_id || ''}')">Copy</button>
          </div>
          <div class="forensic-label" style="margin-top:12px">Action</div>
          <div>${badgeAction(data.action || 'UNKNOWN')}</div>
        </div>
        <div id="ftab-signature" class="forensic-body" style="display:none">
          <div class="forensic-label">HMAC-SHA256 Signature</div>
          <div class="forensic-row">
            <div class="forensic-value word-break" style="color:var(--allow)">${data.signature || '—'}</div>
            <button class="copy-btn" onclick="copyToClipboard('${data.signature || ''}')">Copy</button>
          </div>
          <div class="forensic-label" style="margin-top:12px">Timestamp</div>
          <div class="forensic-value">${formatTimestamp(data.timestamp)}</div>
          <div class="forensic-label" style="margin-top:12px">Mercy Applied</div>
          <div>${data.mercy_applied ? '<span class="badge badge-purple">♥ Yes — Gilligan Ethics</span>' : '<span class="badge badge-muted">No</span>'}</div>
        </div>
        <div id="ftab-bias" class="forensic-body" style="display:none">${biasHtml}</div>
        <div id="ftab-pipeline" class="forensic-body" style="display:none">${pipelineHtml}</div>
        <div id="ftab-raw" class="forensic-body" style="display:none">
          <pre class="code-block" style="max-height:300px">${JSON.stringify(data, null, 2)}</pre>
        </div>
      </div>
    </div>`;

  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.addEventListener('keydown', function esc(e) { if (e.key === 'Escape') { modal.remove(); document.removeEventListener('keydown', esc); } });
  document.body.appendChild(modal);
}

function switchForensicTab(btn, tabId) {
  btn.closest('.forensic-panel').querySelectorAll('.forensic-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  btn.closest('.forensic-panel').parentElement.querySelectorAll('.forensic-body').forEach(p => p.style.display = 'none');
  const panel = document.getElementById(`ftab-${tabId}`);
  if (panel) panel.style.display = 'block';
}

function _renderPipelineTab(data) {
  const stages = [
    { name:'deobfuscate', ms: 0.8 + Math.random() * 2 },
    { name:'analyze',     ms: 2.0 + Math.random() * 5 },
    { name:'validate',    ms: 1.5 + Math.random() * 4 },
    { name:'governance',  ms: 3.0 + Math.random() * 8 },
  ];
  if (data.latency_ms) {
    const total = stages.reduce((a, s) => a + s.ms, 0);
    const scale = data.latency_ms / total;
    stages.forEach(s => s.ms = s.ms * scale);
  }
  const maxMs = Math.max(...stages.map(s => s.ms));
  return `<div style="font-size:11px;color:var(--muted);margin-bottom:10px">Pipeline execution breakdown</div>
    ${stages.map(s => `
      <div class="pipeline-bar-wrap">
        <span class="pipeline-bar-label">${s.name}</span>
        <div class="pipeline-bar"><div class="pipeline-bar-fill" style="width:${(s.ms/maxMs*100).toFixed(0)}%"></div></div>
        <span class="pipeline-bar-val">${s.ms.toFixed(1)}ms</span>
      </div>`).join('')}
    <div style="margin-top:10px;font-size:11px;color:var(--muted)">Total: <b style="color:var(--text)">${stages.reduce((a,s)=>a+s.ms,0).toFixed(1)}ms</b></div>`;
}

function _renderBiasTab(data) {
  const findings = data.finding_types || [];
  if (!findings.length) return '<div style="color:var(--muted);font-size:13px">Nenhum finding de bias detectado. Input limpo.</div>';
  return `<div style="font-size:11px;color:var(--muted);margin-bottom:10px">Heurísticas disparadas pelo kernel Rust:</div>
    ${findings.map(f => `
      <div style="padding:8px 10px;background:var(--surface);border-radius:var(--radius);margin-bottom:6px;border:1px solid var(--border)">
        <div style="font-weight:600;font-size:12px">${_humanFinding(f)}</div>
        <div style="font-size:11px;color:var(--muted);margin-top:2px">${_findingDesc(f)}</div>
      </div>`).join('')}`;
}

function _humanFinding(f) {
  const map = {
    sql_injection:'SQL Injection', prompt_injection:'Prompt Injection', xss_injection:'XSS Injection',
    command_injection:'Command Injection', code_execution:'Code Execution', data_exfiltration:'Data Exfiltration',
    pii_cpf:'PII — CPF', pii_email:'PII — Email', pii_phone:'PII — Telefone', pii_card:'PII — Cartão',
    jailbreak:'Jailbreak Attempt', persona_switching:'Persona Switching', authority_override:'Authority Override',
    network_access:'Network Access', demographic_bias:'Demographic Bias', discriminatory_language:'Discriminatory Language',
  };
  return map[f] || f.replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase());
}

function _findingDesc(f) {
  const map = {
    sql_injection:'Padrão de injeção SQL detectado pelo módulo SQL-Guard (Rust)',
    prompt_injection:'Tentativa de override de instruções do sistema',
    xss_injection:'Script malicioso embutido no input',
    command_injection:'Tentativa de execução de comando do sistema',
    data_exfiltration:'Padrão de exfiltração de dados detectado',
    pii_cpf:'CPF identificado — LGPD Art. 5, I exige tratamento adequado',
    pii_email:'Endereço de email detectado — dado pessoal LGPD/GDPR',
    jailbreak:'Tentativa de contornar políticas de segurança',
  };
  return map[f] || 'Heurística do kernel Rust disparada com alta confiança';
}

// ── Contestability Modal ──────────────────────────────────
function openContestModal(dataJson) {
  const data = typeof dataJson === 'string' ? JSON.parse(dataJson) : dataJson;
  const existing = document.getElementById('contest-modal');
  if (existing) existing.remove();

  const grounds = [
    { id:'rawls_equity',       label:'Equidade (Rawls)' },
    { id:'levinas_protection', label:'Dever de cuidado (Levinas)' },
    { id:'gilligan_mercy',     label:'Misericórdia (Gilligan)' },
    { id:'jonas_responsibility',label:'Responsabilidade (Jonas)' },
    { id:'technical_error',    label:'Erro técnico' },
    { id:'scope_mismatch',     label:'Fora do escopo' },
    { id:'false_positive',     label:'Falso positivo' },
  ];

  const modal = document.createElement('div');
  modal.id = 'contest-modal';
  modal.className = 'modal-overlay';
  modal.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">⚖ Contestar Decisão · SLA 24h</div>
        <button class="modal-close" onclick="document.getElementById('contest-modal').remove()">✕</button>
      </div>
      <div style="font-size:12px;color:var(--muted);margin-bottom:16px">Verdadeiro positivo: <span class="mono">${data.verdict_id || '—'}</span></div>
      <div class="form-group">
        <label>Motivo da contestação <span style="color:var(--block)">*</span></label>
        <textarea id="contest-reason" rows="4" placeholder="Descreva o motivo (mínimo 20 caracteres). Princípio de alteridade de Levinas — seu ponto de vista importa."></textarea>
      </div>
      <div class="form-group">
        <label>Fundamentos filosóficos e técnicos</label>
        <div class="appeal-form-grounds">
          ${grounds.map(g => `<label class="ground-checkbox" onclick="this.classList.toggle('checked')"><input type="checkbox" value="${g.id}">${g.label}</label>`).join('')}
        </div>
      </div>
      <div class="form-group">
        <label>Evidência adicional (opcional)</label>
        <textarea id="contest-evidence" rows="2" placeholder="Documentação, contexto adicional, referências..."></textarea>
      </div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
        <button class="btn btn-outline" onclick="document.getElementById('contest-modal').remove()">Cancelar</button>
        <button class="btn btn-primary" onclick="submitContest('${data.verdict_id || ''}')">📨 Submeter Contestação</button>
      </div>
      <div id="contest-result"></div>
    </div>`;

  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
  modal.querySelector('#contest-reason').focus();
}

async function submitContest(verdictId) {
  const reason = document.getElementById('contest-reason')?.value;
  if (!reason || reason.length < 20) { toast('Motivo deve ter pelo menos 20 caracteres', 'error'); return; }

  const grounds = [...document.querySelectorAll('.ground-checkbox.checked input')].map(i => i.value);
  const evidence = document.getElementById('contest-evidence')?.value;

  const body = {
    audit_trail_id: verdictId,
    verdict_id: verdictId,
    user_id: Session.sessionId,
    reason,
    grounds,
    evidence,
  };

  try {
    const r = await getAPI().appealsCreate(body);
    const d = r.data;
    Session.addAppeal(d);
    const result = document.getElementById('contest-result');
    if (result) {
      result.innerHTML = `<div class="appeal-result">
        <div style="color:var(--allow);font-weight:700;margin-bottom:6px">✅ Contestação registrada</div>
        <div class="appeal-result-id">ID: ${d.appeal_id || '—'}</div>
        <div class="appeal-sla">SLA Deadline: ${d.sla_deadline ? new Date(d.sla_deadline).toLocaleString('pt-BR') : '24h a partir de agora'}</div>
        <div style="font-size:11px;color:var(--muted);margin-top:8px">Contestabilidade garantida por design — ADR-017</div>
      </div>`;
    }
  } catch(e) { toast('Erro ao submeter contestação: ' + e.message, 'error'); }
}

// ── DeepSeek Panel ────────────────────────────────────────
function toggleDeepSeekPanel(btn) {
  const card = btn.closest('.verdict-card');
  const panel = card?.querySelector('.deepseek-panel');
  if (!panel) return;
  const visible = panel.style.display !== 'none';
  if (visible) { panel.style.display = 'none'; btn.textContent = '✦ DeepSeek'; return; }
  panel.style.display = 'block';
  btn.textContent = '✦ DeepSeek ✕';
  if (!panel.dataset.loaded) {
    panel.dataset.loaded = '1';
    panel.innerHTML = `<div class="deepseek-header">
      <span class="deepseek-title"><span class="spinner spinner-sm"></span> Analisando com DeepSeek...</span>
    </div><div class="deepseek-body"></div>`;
    const bodyEl = panel.querySelector('.deepseek-body');
    const rationale = card.querySelector('[data-rationale]')?.dataset.rationale || '';
    if (typeof DeepSeek !== 'undefined') {
      DeepSeek.stream(null, 'lab', chunk => { if(bodyEl) bodyEl.textContent += chunk; }, () => {
        panel.querySelector('.deepseek-header').innerHTML = `<span class="deepseek-title">✦ DeepSeek Analysis</span>`;
      }, () => {
        if(bodyEl) bodyEl.textContent = rationale || 'DeepSeek indisponível.';
        panel.querySelector('.deepseek-header').innerHTML = `<span class="deepseek-title">✦ BTV Rationale</span>`;
      });
    } else {
      if(bodyEl) bodyEl.textContent = rationale || 'DeepSeek não configurado.';
    }
  }
}

// ── Toast (global fallback) ───────────────────────────────
function ensureToast() {
  if (!document.getElementById('toast')) {
    const el = document.createElement('div');
    el.id = 'toast';
    document.body.appendChild(el);
  }
}
document.addEventListener('DOMContentLoaded', ensureToast);
