# ADR 0011 — Policy Engine: Núcleo v1

**Status:** ✅ Aceito  
**Data:** 2026-05-28  
**Autores:** Engenharia de Plataforma e Governança do BTV  
**Revisores:** AI Squad — Arquiteta (Opus) + Reviewer (Opus)  
**Supersede:** —  
**Supersedido por:** —  
**Relacionados:** ADR 0006 (Policy-as-Code), ADR 0042 (Policy-as-Code v2), ADR 0063 (TechnicalEvidence 9596 bytes)

---

## Contexto

Ambientes de Core Banking demandam a avaliação dinâmica de regras de conformidade, limites de crédito e análise de risco com base em arquivos de configuração declarativos (YAML). O uso de motores de avaliação de expressões dinâmicas genéricas (*runtime evaluation*) em linguagens de alto nível introduz riscos críticos para a postura de segurança do BTV:

- **Injeção de Código e Bypass de Escopo:** Strings interpretadas dinamicamente podem ser manipuladas para acessar recursos do sistema de arquivos ou vazar contextos entre tenants, violando o invariante de isolamento multi-tenant.
- **Não-Determinismo de RAM e CPU:** Loops maliciosos ou recursão em arquivos de políticas podem estourar a pilha de execução (OOM) ou violar o SLA transacional de `<50ms p99` exigido pela esteira do Kernel Rust.
- **Vazamento de Exceções Nativo:** Falhas de parsing ou erros de tipo em tempo de execução na camada interceptadora podem derrubar o processo host (JVM), violando a postura Fail-Secure da plataforma e comprometendo a continuidade do serviço.

O arquivo físico original (`0011-policy-engine.md`) existia como placeholder estrutural no índice mestre. Este ADR formaliza a decisão técnica de como o motor isola matematicamente essas avaliações.

---

## Decisão

Adotar o **Avaliador Estático de Expressões de Controle Integrado (PolicyEngine)**, implementado exclusivamente no Kernel Nativo em Safe Rust, atuando sob o paradigma de **interpretação baseada em Árvore de Sintaxe Abstrata (AST) fechada e fortemente tipada**.

A arquitetura de processamento obedecerá rigidamente aos critérios de design descritos abaixo.

---

## Arquitetura

### 1. Gramática BNF Restrita e Parser sem Avaliação Dinâmica

O motor **não utilizará** funções do tipo `eval()` ou mecanismos de reflexão. O parser de políticas consumirá strings de expressão (ex.: `rawls_safety_threshold > 0.80`) e as traduzirá em tokens estritos mapeados por um `enum` do Rust (`ExpressionAST`). Qualquer operador, caractere ou chamada de função que não pertença à tabela de símbolos definida em tempo de compilação dispara imediatamente erro estrito (`PolicyParseError`) e coloca a transação em estado de **Hard BLOCK**.

```
Expression  ::= Operand Operator Operand
Operand     ::= Identifier | Literal
Operator    ::= ">" | "<" | ">=" | "<=" | "==" | "!="
Identifier  ::= [a-z_][a-z0-9_]*   /* tabela de símbolos em compile-time */
Literal     ::= [0-9]+(".")[0-9]+  /* f64, sem strings livres */
```

Qualquer token fora desta gramática BNF é rejeitado no estágio de lexing, antes de qualquer avaliação de valor.

### 2. Separação de Contexto Dinâmico por Tenant

O estado dinâmico necessário para avaliar as equidades de Rawls (`DIR`) ou o drift de Jonas (`PSI`) será injetado em uma estrutura de memória isolada (`EvaluationContext`), instanciada de forma **efêmera por transação**. O escopo de leitura do motor é estritamente limitado por essa cópia de dados, bloqueando qualquer acesso colateral à memória do heap compartilhado.

```rust
// Ciclo de vida estritamente acoplado à transação
let ctx = EvaluationContext::from_transaction(&tx_data);
let verdict = policy_engine.evaluate(&ast, &ctx)?;
// ctx é dropped aqui — resíduos apagados via Drop do Rust
```

O `Drop` do Rust garante que resíduos de dados demográficos de um cliente sejam apagados imediatamente após o veredicto, sem dependência de GC externo.

### 3. Contenção de Pânico e Isolamento ABI na Fronteira FFI

A integração com o adaptador gRPC ou a ponte JNI será encapsulada em blocos estáveis de captura de exceções nativas (`catch_unwind`). Se o motor sofrer uma instabilidade matemática imprevista (como uma divisão por zero não detectada estaticamente), o pânico nativo é retido na fronteira de tipo. O Rust reverterá o erro de forma controlada, emitindo o código `E150` para o host Java, forçando o comportamento Fail-Closed **sem desestabilizar o microsserviço interceptador**.

```rust
let result = std::panic::catch_unwind(|| {
    policy_engine.evaluate(&ast, &ctx)
});
match result {
    Ok(verdict) => verdict,
    Err(_)      => Verdict::block_with_code(ErrorCode::E150),
}
```

---

## Consequências

### Positivas

- **Imunidade contra Injection:** A eliminação de interpretadores de strings genéricos bloqueia tentativas de injeção de payload semântico na camada de regras de negócio.
- **Previsibilidade e SLA Garantido:** A avaliação da árvore AST customizada possui complexidade de tempo linear \(\mathcal{O}(N)\) em relação ao número de nós da expressão, eliminando caminhos de execução infinitos ou travamentos de thread.
- **Isolamento de Memória Real:** O acoplamento estrito entre o ciclo de vida do `EvaluationContext` e a transação garante que resíduos de dados demográficos de um cliente sejam apagados via `Drop` do Rust imediatamente após o veredicto.

### Trade-offs

- **Sobrecarga de Manutenção da Gramática:** Adicionar novas funções matemáticas ou métricas de equidade ao motor de políticas exige a alteração explícita da tabela de símbolos `ExpressionAST` e recompilação do binário `.so`, impedindo atualizações dinâmicas da gramática em tempo de execução. Este é um custo deliberado: a imutabilidade da gramática em runtime é a garantia de segurança central desta decisão.

---

## Validação

O motor de políticas será considerado válido quando a suíte de testes unitários localizada em [`rust/kernel/tests/contextual_decisions.rs`](../../rust/kernel/tests/contextual_decisions.rs) atestar:

1. **Rejeição de payloads inválidos:** Rejeição de payloads contendo tentativas de fuga sintática ou caracteres fora da especificação da tabela ASCII de símbolos permitidos.
2. **Contenção de pânico:** Contenção com código de erro `E150` limpo durante picos de estresse e reinicialização assíncrona do contexto dinâmico do tenant.
3. **Isolamento de contexto:** Ausência de vazamento de `EvaluationContext` entre transações concorrentes de tenants distintos.

> **Referência física verificada:** `rust/kernel/tests/contextual_decisions.rs` — SHA `4d477554`, 8.852 bytes, confirmado no HEAD `8be7068` em 2026-05-28.

---

## Registro de Revisões

| Versão | Data | Alteração |
|:---|:---|:---|
| v1.0.0 | 2026-05-28 | Materialização do stub — conteúdo arquitetural completo registrado. Auditoria forense prévia confirmou densidade de testes em `contextual_decisions.rs` (8.852 bytes). |
