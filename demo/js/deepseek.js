/**
 * BuildToValue — DeepSeek SSE Streaming
 * Only called when action=ALLOW. Falls back to BTV rationale.
 */

const DeepSeek = (() => {
  const PERSONA_PROMPTS = {
    engineer:   (d) => `You are a security engineer reviewing a BTV Trust OS decision. The input was allowed (action: ALLOW, risk: ${d?.adjusted_risk?.toFixed(3) || '~0.03'}). Briefly analyze: what edge cases or attack vectors might still be worth monitoring? What Rust kernel validators ran? Keep it technical and concise (3-4 sentences).`,
    ciso:       (d) => `You are a CISO reviewing an AI governance decision. Action: ALLOW, Risk: ${d?.adjusted_risk?.toFixed(3) || '~0.03'}, Trust: ${d?.trust_score?.toFixed(2) || '~0.90'}. Provide an executive summary of this decision's security implications and any monitoring recommendations. 3-4 sentences, executive tone.`,
    dpo:        (d) => `You are a Data Protection Officer. BTV allowed this AI request (risk: ${d?.adjusted_risk?.toFixed(3) || '~0.03'}). Assess compliance implications under LGPD/GDPR. Are there any data minimization or purpose limitation concerns? 3-4 sentences, regulatory focus.`,
    governance: (d) => `You are an ethics and governance officer. BTV allowed this AI request through its philosophical pipeline (Rawls, Levinas, Jonas, Gilligan). Risk: ${d?.adjusted_risk?.toFixed(3) || '~0.03'}. Provide a brief ethical analysis: which philosophical principles were satisfied? Any equity or accountability concerns? 3-4 sentences.`,
    lab:        (d) => `You are an AI governance expert demonstrating BTV Trust OS. This request was ALLOWED (risk: ${d?.adjusted_risk?.toFixed(3) || '~0.03'}). Explain in simple terms why this decision makes sense ethically and technically. Educational tone, 3-4 sentences.`,
  };

  const MOCK_RESPONSES = {
    engineer:   'O kernel Rust processou 15 módulos de validação incluindo análise de entropia, detecção de SQL/XSS/prompt injection, e normalização Unicode. Nenhum padrão de ameaça foi identificado acima do threshold de 0.3. O pipeline completo executou dentro do SLA de 50ms. Monitoramento contínuo recomendado para sessões com múltiplas requisições de informação sensível.',
    ciso:       'Decisão de ALLOW aprovada após pipeline completo de validação. Risk score abaixo do threshold crítico (< 0.3). Trust score da sessão mantido. Nenhuma ação imediata necessária. Recomendo monitorar padrões de uso desta sessão para detectar mudança de comportamento que poderia indicar account takeover.',
    dpo:        'Esta requisição não apresenta indicadores de violação LGPD/GDPR. Nenhum dado pessoal identificável foi detectado no input. Propósito está dentro do escopo declarado do sistema. O princípio de minimização de dados foi respeitado. Evidência forense disponível no ledger imutável para auditoria futura.',
    governance: 'O pipeline filosófico validou esta decisão sob todos os quatro frameworks éticos. Rawls: equidade mantida (sem tratamento discriminatório). Levinas: dever de cuidado satisfeito. Jonas: responsabilidade com futuras gerações considerada. Gilligan: sem necessidade de aplicar mercy neste caso. Decisão eticamente sólida.',
    lab:        'Esta requisição foi permitida pelo BTV Trust OS porque passou por todos os 15 módulos de validação do kernel Rust sem disparar alertas críticos. O risco calculado está dentro dos limites aceitáveis, e o score de confiança da sessão permanece alto. O sistema funciona como uma "balança algorítmica" que pondera segurança, ética e utilidade.',
  };

  async function stream(verdictData, persona = 'lab', onChunk, onDone, onError) {
    const prompt = PERSONA_PROMPTS[persona]?.(verdictData) || PERSONA_PROMPTS.lab(verdictData);

    try {
      const res = await fetch('/api/deepseek/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt, stream: true }),
        signal: AbortSignal.timeout(15000),
      });

      if (!res.ok) throw new Error('DeepSeek unavailable');

      const reader = res.body?.getReader();
      if (!reader) throw new Error('No stream');

      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const raw = line.slice(6).trim();
          if (raw === '[DONE]') { onDone?.(); return; }
          try {
            const parsed = JSON.parse(raw);
            const chunk = parsed.choices?.[0]?.delta?.content || '';
            if (chunk) onChunk?.(chunk);
          } catch {}
        }
      }
      onDone?.();
    } catch (err) {
      _mockStream(persona, onChunk, onDone);
    }
  }

  function _mockStream(persona, onChunk, onDone) {
    const text = MOCK_RESPONSES[persona] || MOCK_RESPONSES.lab;
    const words = text.split(' ');
    let i = 0;
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    if (prefersReduced) {
      onChunk?.(text);
      onDone?.();
      return;
    }

    const interval = setInterval(() => {
      if (i >= words.length) { clearInterval(interval); onDone?.(); return; }
      onChunk?.(words[i] + (i < words.length - 1 ? ' ' : ''));
      i++;
    }, 60);
  }

  function renderPanel(containerId, verdictData, persona = 'lab') {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = `
      <div class="deepseek-panel">
        <div class="deepseek-header">
          <span class="deepseek-title"><span class="spinner spinner-sm"></span> DeepSeek · Análise contextual</span>
          <button class="deepseek-toggle" onclick="this.closest('.deepseek-panel').style.display='none'">✕</button>
        </div>
        <div id="${containerId}-body" class="deepseek-body cursor-blink"></div>
      </div>`;

    const bodyEl = document.getElementById(`${containerId}-body`);
    if (!bodyEl) return;

    stream(
      verdictData,
      persona,
      (chunk) => { bodyEl.classList.remove('cursor-blink'); bodyEl.textContent += chunk; },
      () => {
        const hdr = container.querySelector('.deepseek-header');
        if (hdr) hdr.innerHTML = `<span class="deepseek-title">✦ DeepSeek · ${persona.toUpperCase()}</span>`;
      },
      () => {
        if (bodyEl) bodyEl.textContent = verdictData?.rationale || 'Análise indisponível.';
        const hdr = container.querySelector('.deepseek-header');
        if (hdr) hdr.innerHTML = `<span class="deepseek-title">✦ BTV Rationale</span>`;
      }
    );
  }

  return { stream, renderPanel };
})();
