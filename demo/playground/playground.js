// Playground do Portal do Desenvolvedor.
// Carrega cenários estáticos (./scenarios/*.json), simula a chamada ao gateway
// e renderiza o resultado — incluindo o painel de contestabilidade educativo
// para bloqueios HTTP 451.
//
// Princípios (ver docs/developer/concepts/):
//   - Fail-secure first: cenário block-451 é o primeiro listado.
//   - Transparência radical: simulações de tempo trazem badge inamovível.
//   - Orquestração: links sempre apontam ao conteúdo canônico em docs/.

const SCENARIOS = [
  { id: "block-451", file: "scenarios/block-451.json", label: "Bloqueio HIPAA (HTTP 451) — fail-secure" },
  { id: "contestation", file: "scenarios/contestation.json", label: "Contestação após bloqueio" },
  { id: "sla-24h", file: "scenarios/sla-24h.json", label: "SLA de 24h (simulação didática)" },
];

const list = document.getElementById("scenario-list");
const section = document.getElementById("result-section");
const out = document.getElementById("result");

for (const s of SCENARIOS) {
  const div = document.createElement("div");
  div.className = "btv-scenario";
  div.textContent = s.label;
  div.addEventListener("click", () => runScenario(s));
  list.appendChild(div);
}

async function runScenario(s) {
  section.hidden = false;
  out.innerHTML = "<p>Carregando…</p>";
  let data;
  try {
    data = await fetch(s.file).then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    });
  } catch (e) {
    out.innerHTML = `<div class="btv-result block">Falha ao carregar cenário: ${e}</div>`;
    return;
  }
  render(data);
}

function render(data) {
  const isBlock = data.decision === "BLOCK";
  const decisionClass = isBlock ? "block" : "allow";
  const simBadge = data.simulated_time
    ? `<p><span class="btv-sim-badge">[SIMULAÇÃO DIDÁTICA — ESTADO DO LEDGER NÃO AFETADO]</span></p>`
    : "";
  let html = `
    <div class="btv-result ${decisionClass}">
      ${simBadge}
      <h3>${data.decision}</h3>
      <p><strong>Razão:</strong> <code>${data.reason ?? "—"}</code></p>
      <p><strong>Hash da evidência:</strong> <code>${data.evidence_hash ?? "—"}</code></p>
      <details>
        <summary>JSON completo</summary>
        <pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>
      </details>
      <p>
        <a href="../../docs/developer/tutorials/03-verify-evidence-cli.md">
          Auditar fora do navegador com <code>btv-cli verify</code>
        </a>
      </p>
    </div>
  `;
  if (isBlock && data.contestability) {
    html += `
      <div class="btv-contestability">
        <h4>ContestabilityLoop</h4>
        <p>
          Este bloqueio admite contestação. O usuário final tem direito a apelar
          via <code>${data.contestability.endpoint}</code>, com SLA de
          <strong>${data.contestability.sla_hours}h</strong>
          (<a href="../../docs/adr/0017-contestability-loop.md">ADR-0017</a>).
        </p>
        <p>
          O protocolo de mediação estruturada é definido em
          <a href="../../docs/adr/0047-contestability-structured-mediation-protocol.md">ADR-0047</a>.
        </p>
        <ol>
          <li>Apresentar a razão estruturada ao usuário.</li>
          <li>Coletar argumentos via formulário do SDK.</li>
          <li>Aguardar resolução em até 24h.</li>
        </ol>
      </div>
    `;
  }
  out.innerHTML = html;
}

function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
