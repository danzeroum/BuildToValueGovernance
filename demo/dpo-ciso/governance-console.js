// Governance Console — orquestrador vanilla JS.
//
// Responsabilidades:
//   - Roteamento entre os três painéis (Dashboard, Audit, Editor).
//   - i18n PT/EN sincronizado com o portal mkdocs (lang_select persiste em
//     localStorage; toggles disparam re-render).
//   - Algoritmo Gilligan S1-S6 (ADR-072) — única fonte para o Dashboard
//     classificar appeals.
//
// Princípio inviolável: nenhuma chamada de runtime (POST /reload, etc.).
// O Policy Editor (Painel 1) gera YAML + assinatura local e instrui o usuário
// a abrir PR — nunca toca produção diretamente.
'use strict';

window.GovernanceConsole = (function () {
  const I18N = {
    pt: {
      tab_dashboard: 'Painel de Conformidade · LGPD/AI Act',
      tab_audit: 'Trilha Forense · Evidências Imutáveis',
      tab_editor: 'Editor de Políticas · Controle de Risco',
      // Hero contextual
      hero_title: 'Governance Console',
      hero_sub: 'Conformidade, Auditoria e Políticas em um só lugar — sem tocar o runtime em produção.',
      hero_dpo_role: 'DPO · Proteção de Dados',
      hero_dpo_desc: 'Monitora conformidade LGPD/AI Act em tempo real com evidência forense auditável. Gera FRIA com um clique.',
      hero_ciso_role: 'CISO · Segurança da Informação',
      hero_ciso_desc: 'Visualiza riscos, políticas ativas e trilha de auditoria imutável. Detecta quebras de SLA e anomalias.',
      hero_cta: 'Entendido, continuar →',
      // Banner
      banner_link: 'Ver Ledger Real →',
      banner_failsecure: 'Decisões reais usam BLAKE3 + HMAC-SHA256 e são irreversíveis por design (Fail-Secure).',
      // Anatomy card
      anatomy_title: 'O que você está vendo',
      anatomy_body: 'Cada linha representa uma decisão tomada por um agente de IA. A coluna "Evidência" é um hash BLAKE3 — a impressão digital forense imutável dessa decisão. "Resultado" indica o que o Gatekeeper executou.',
      // Footer nav
      footer_back: '← Perfil DPO',
      footer_current: 'Governance Console',
      footer_next: 'Ledger Explorer →',
      // Glossary
      glossary_title: 'Glossário Técnico',
      glossary_gilligan_term: 'Gilligan S1–S6',
      glossary_gilligan_def: 'Algoritmo de classificação de apelações por ética do cuidado (ADR-072). S1 = >18h restantes, S6 = expirado.',
      glossary_fria_term: 'FRIA',
      glossary_fria_def: 'Avaliação de Impacto aos Direitos Fundamentais — exigida pelo EU AI Act para sistemas de alto risco.',
      glossary_blake3_term: 'BLAKE3',
      glossary_blake3_def: 'Função hash criptográfica que garante a imutabilidade do ledger. Irreversível por design.',
      glossary_hmac_term: 'HMAC-SHA256',
      glossary_hmac_def: 'Assinatura de integridade do EthicalVerdict. Prova que a decisão não foi adulterada após emissão.',
      // Tooltips
      badge_allow_tip: 'Ação permitida — sem restrições identificadas.',
      badge_block_tip: 'Decisão bloqueada por violação de política — evidência forense gerada automaticamente.',
      badge_educate_tip: 'Ação permitida com alerta pedagógico ao usuário.',
      badge_redact_tip: 'Dados sensíveis redigidos antes do output — proteção LGPD/GDPR ativa.',
      // Dashboard
      dash_title: 'Compliance Dashboard',
      dash_intro: 'Leitura ao vivo de evidências do gateway. Os SLAs de contestação são classificados pelos cenários S1–S6 do algoritmo Gilligan (ADR-072).',
      dash_metric_decisions: 'Decisões hoje',
      dash_metric_appeals: 'Appeals pendentes',
      dash_metric_blocks: 'Bloqueios (24h)',
      dash_metric_sla_breach: 'Quebras de SLA',
      dash_appeals_title: 'Appeals pendentes (SLA Gilligan)',
      dash_appeals_help: 'Cenários S1 (>18h) a S6 (expirado). S5 dispara escalonamento automático via data/policies/webhooks.yaml.',
      col_id: 'ID', col_agent: 'Agente', col_reason: 'Motivo', col_remaining: 'Tempo restante', col_scenario: 'Cenário', col_severity: 'Severidade',
      dash_frameworks_title: 'Frameworks ativos',
      dash_frameworks_help: 'Lidos de data/policies/frameworks/. Cada plugin habilita verificadores em python/buildtovalue/compliance/.',
      // Audit
      audit_title: 'Audit Trail',
      audit_intro: 'Lista decisões com explicação em linguagem natural. Exporte o PDF forense para auditoria fora do navegador.',
      audit_filter_risk: 'Risco', audit_filter_period: 'Período', audit_filter_agent: 'Agente', audit_filter_verdict: 'Veredito',
      audit_export: 'Exportar Evidência Forense (PDF)',
      audit_explain: 'Explicação',
      audit_hash: 'Hash BLAKE3',
      audit_hmac: 'HMAC-SHA256',
      audit_verify_hint: 'Para auditar fora do navegador:',
      // Editor
      editor_title: 'Policy Editor — Painel Visual',
      editor_intro: 'Este formulário NUNCA toca o runtime. Ele gera YAML, valida contra o JSON Schema, calcula assinatura local e instrui você a abrir um Pull Request em data/policies/. O kernel só aceita políticas com assinatura Ed25519 verificada (ADR-064).',
      editor_sector: 'Setor', editor_threshold: 'Threshold de risco (REPORT)', editor_hard_block: 'Termos de bloqueio absoluto',
      editor_bias: 'Declaração de viés conhecido',
      editor_bias_hint: 'Constitucional (Rawls blind-test). Liste vieses que o autor da política reconhece — mitigantes em campo abaixo.',
      editor_mitigations: 'Mitigações',
      editor_jurisdiction: 'Jurisdição', editor_jur_hint: 'Ex: BR,EU — para aplicar LGPD + GDPR simultaneamente.',
      editor_review: 'Revisar política gerada',
      editor_yaml: 'YAML gerado (para PR em data/policies/sectors/<setor>.yaml)',
      editor_validate: 'Validar contra schema',
      editor_sign: 'Calcular assinatura local (HMAC)',
      editor_flow: 'Fluxo obrigatório (não pulável):',
      editor_step1: '1. Validação client-side (JSON Schema).',
      editor_step2: '2. validate_policy_schema.py (server-side, CI).',
      editor_step3: '3. policy_signer.py → assinatura Ed25519 da Ethics Committee (ADR-064).',
      editor_step4: '4. PR em data/policies/ → CI (alignment_regression + policy-blind-test).',
      editor_step5: '5. Merge manual → reload assinado pelo kernel.',
      editor_warning: 'Esta UI NUNCA executa POST /reload. Bypass dessa cadeia = violação constitucional.',
      validation_ok: 'Schema válido.',
      validation_fail: 'Schema inválido:',
      sig_ok: 'Assinatura HMAC local calculada. Próximo passo: rode scripts/policy_signer.py com a chave da Ethics Committee.',
    },
    en: {
      tab_dashboard: 'Compliance Dashboard · LGPD/AI Act',
      tab_audit: 'Forensic Trail · Immutable Evidence',
      tab_editor: 'Policy Editor · Risk Control',
      // Hero contextual
      hero_title: 'Governance Console',
      hero_sub: 'Compliance, Audit, and Policies in one place — without touching the production runtime.',
      hero_dpo_role: 'DPO · Data Protection',
      hero_dpo_desc: 'Monitors LGPD/AI Act compliance in real time with auditable forensic evidence. Generates FRIA in one click.',
      hero_ciso_role: 'CISO · Information Security',
      hero_ciso_desc: 'Visualizes risks, active policies, and an immutable audit trail. Detects SLA breaches and anomalies.',
      hero_cta: 'Got it, continue →',
      // Banner
      banner_link: 'View Real Ledger →',
      banner_failsecure: 'Real decisions use BLAKE3 + HMAC-SHA256 and are irreversible by design (Fail-Secure).',
      // Anatomy card
      anatomy_title: 'What you are seeing',
      anatomy_body: 'Each row represents a decision made by an AI agent. The "Evidence" column is a BLAKE3 hash — the immutable forensic fingerprint of that decision. "Outcome" indicates what the Gatekeeper executed.',
      // Footer nav
      footer_back: '← DPO Profile',
      footer_current: 'Governance Console',
      footer_next: 'Ledger Explorer →',
      // Glossary
      glossary_title: 'Technical Glossary',
      glossary_gilligan_term: 'Gilligan S1–S6',
      glossary_gilligan_def: 'Appeal classification algorithm based on ethics of care (ADR-072). S1 = >18h remaining, S6 = expired.',
      glossary_fria_term: 'FRIA',
      glossary_fria_def: 'Fundamental Rights Impact Assessment — required by the EU AI Act for high-risk AI systems.',
      glossary_blake3_term: 'BLAKE3',
      glossary_blake3_def: 'Cryptographic hash function that ensures ledger immutability. Irreversible by design.',
      glossary_hmac_term: 'HMAC-SHA256',
      glossary_hmac_def: 'Integrity signature of the EthicalVerdict. Proves the decision was not tampered with after issuance.',
      // Tooltips
      badge_allow_tip: 'Action allowed — no restrictions identified.',
      badge_block_tip: 'Decision blocked by policy violation — forensic evidence generated automatically.',
      badge_educate_tip: 'Action allowed with pedagogical alert to the user.',
      badge_redact_tip: 'Sensitive data redacted before output — active LGPD/GDPR protection.',
      // Dashboard
      dash_title: 'Compliance Dashboard',
      dash_intro: 'Live read of gateway evidence. Appeal SLAs are classified by Gilligan S1–S6 scenarios (ADR-072).',
      dash_metric_decisions: 'Decisions today',
      dash_metric_appeals: 'Pending appeals',
      dash_metric_blocks: 'Blocks (24h)',
      dash_metric_sla_breach: 'SLA breaches',
      dash_appeals_title: 'Pending appeals (Gilligan SLA)',
      dash_appeals_help: 'Scenarios S1 (>18h) through S6 (expired). S5 triggers auto-escalation via data/policies/webhooks.yaml.',
      col_id: 'ID', col_agent: 'Agent', col_reason: 'Reason', col_remaining: 'Remaining', col_scenario: 'Scenario', col_severity: 'Severity',
      dash_frameworks_title: 'Active frameworks',
      dash_frameworks_help: 'Read from data/policies/frameworks/. Each plugin enables checkers in python/buildtovalue/compliance/.',
      audit_title: 'Audit Trail',
      audit_intro: 'Lists decisions with natural-language explanations. Export the forensic PDF for out-of-browser audit.',
      audit_filter_risk: 'Risk', audit_filter_period: 'Period', audit_filter_agent: 'Agent', audit_filter_verdict: 'Verdict',
      audit_export: 'Export Forensic Evidence (PDF)',
      audit_explain: 'Explanation',
      audit_hash: 'BLAKE3 hash',
      audit_hmac: 'HMAC-SHA256',
      audit_verify_hint: 'To audit out of the browser:',
      editor_title: 'Policy Editor — Visual Panel',
      editor_intro: 'This form NEVER touches the runtime. It generates YAML, validates it against the JSON Schema, computes a local signature, and instructs you to open a Pull Request against data/policies/. The kernel accepts policies only with a verified Ed25519 signature (ADR-064).',
      editor_sector: 'Sector', editor_threshold: 'Risk threshold (REPORT)', editor_hard_block: 'Hard-block terms',
      editor_bias: 'Known-bias declaration',
      editor_bias_hint: 'Constitutional (Rawls blind-test). List biases the policy author acknowledges — mitigations below.',
      editor_mitigations: 'Mitigations',
      editor_jurisdiction: 'Jurisdiction', editor_jur_hint: 'E.g. BR,EU — to apply LGPD + GDPR simultaneously.',
      editor_review: 'Review generated policy',
      editor_yaml: 'Generated YAML (for PR against data/policies/sectors/<sector>.yaml)',
      editor_validate: 'Validate against schema',
      editor_sign: 'Compute local signature (HMAC)',
      editor_flow: 'Required flow (no skipping):',
      editor_step1: '1. Client-side validation (JSON Schema).',
      editor_step2: '2. validate_policy_schema.py (server-side, CI).',
      editor_step3: '3. policy_signer.py → Ed25519 signature from the Ethics Committee (ADR-064).',
      editor_step4: '4. PR against data/policies/ → CI (alignment_regression + policy-blind-test).',
      editor_step5: '5. Manual merge → kernel performs a signed reload.',
      editor_warning: 'This UI NEVER calls POST /reload. Bypassing this chain = constitutional violation.',
      validation_ok: 'Schema valid.',
      validation_fail: 'Schema invalid:',
      sig_ok: 'Local HMAC signature computed. Next: run scripts/policy_signer.py with the Ethics Committee key.',
    },
  };

  let currentLang = localStorage.getItem('btv-gov-lang') || 'pt';

  const State = {
    panels: { dashboard: null, audit: null, editor: null },
    activeTab: 'dashboard',
  };

  function t(key) { return (I18N[currentLang] && I18N[currentLang][key]) || key; }

  function gilliganScenario(deadlineISO, severityShift = 0) {
    // ADR-072 canonical mapping.
    const remaining = (new Date(deadlineISO) - Date.now()) / 3_600_000; // hours
    let s;
    if (remaining <= 0) s = 6;
    else if (remaining < 2) s = 5;
    else if (remaining < 6) s = 4;
    else if (remaining < 12) s = 3;
    else if (remaining < 18) s = 2;
    else s = 1;
    // Severity may shift UP one level (max S6), never DOWN.
    const shifted = Math.min(6, s + Math.max(0, severityShift));
    return 'S' + shifted;
  }

  function formatRemaining(deadlineISO) {
    const ms = new Date(deadlineISO) - Date.now();
    if (ms <= 0) return currentLang === 'pt' ? 'expirado' : 'expired';
    const h = Math.floor(ms / 3_600_000);
    const m = Math.floor((ms % 3_600_000) / 60_000);
    return `${h}h ${m}m`;
  }

  function setTab(name) {
    State.activeTab = name;
    document.querySelectorAll('nav.gov-tabs button').forEach((b) => {
      b.classList.toggle('active', b.dataset.tab === name);
    });
    document.querySelectorAll('.gov-panel').forEach((p) => {
      p.classList.toggle('active', p.id === `panel-${name}`);
    });
  }

  function setLang(lang) {
    currentLang = lang;
    localStorage.setItem('btv-gov-lang', lang);
    document.documentElement.lang = lang === 'pt' ? 'pt-BR' : 'en';
    document.querySelectorAll('[data-i18n]').forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    // Re-render active panel content
    State.panels.dashboard && State.panels.dashboard.render();
    State.panels.audit && State.panels.audit.render();
    State.panels.editor && State.panels.editor.render();
  }

  function boot() {
    State.panels.dashboard = window.ComplianceDashboard.mount('panel-dashboard', { t, gilliganScenario, formatRemaining, lang: () => currentLang });
    State.panels.audit = window.AuditTrail.mount('panel-audit', { t, lang: () => currentLang });
    State.panels.editor = window.PolicyEditor.mount('panel-editor', { t, lang: () => currentLang });

    document.querySelectorAll('nav.gov-tabs button').forEach((b) => {
      b.addEventListener('click', () => setTab(b.dataset.tab));
    });
    document.getElementById('lang-select').addEventListener('change', (e) => setLang(e.target.value));
    document.getElementById('lang-select').value = currentLang;
    setLang(currentLang);
  }

  return { boot, t, gilliganScenario, formatRemaining };
})();
