# ADR-012: Output Guard & Sanitization

**Status:** 🔒 Planejado (v1.6)
**Crate:** `btv-kernel` (output_guard module)

## Decisão
Implementar um estágio pós-processamento que varre a resposta do Agente de IA em busca de PII vazado (ex: CPF gerado alucinadamente) e aplica máscaras (REDACT) antes de entregar ao usuário.