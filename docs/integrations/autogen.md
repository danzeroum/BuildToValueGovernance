# AutoGen — BTVAutoGenGuard

```bash
pip install btv-autogen
```

Filtra mensagens em conversas multi-agente AutoGen. Compatible com `ConversableAgent.register_reply()`.

---

## Uso básico

```python
import autogen
from buildtovalue import BTVClient
from btv_autogen import BTVAutoGenGuard

btv = BTVClient(api_key="...", gateway_url="http://localhost:8080")
guard = BTVAutoGenGuard(
    client=btv,
    session_id="sess-autogen-001",
    profile="general",
)

# Cria agente e registra o guard como primeiro handler
assistant = autogen.AssistantAgent(name="assistant", llm_config=llm_config)
user_proxy = autogen.UserProxyAgent(name="user_proxy")

# Registra o guard para filtrar mensagens recebidas pelo assistente
assistant.register_reply(
    trigger=autogen.ConversableAgent,
    reply_func=guard.check_message,
    position=0,  # roda antes de tudo
)

user_proxy.initiate_chat(assistant, message="Qual é a política de privacidade?")
```

---

## Configuração completa

```python
guard = BTVAutoGenGuard(
    client=btv,
    session_id="sess-001",
    profile="healthcare",
    use_decide=False,               # False: Rust-only (mais rápido)
    block_on=frozenset({"BLOCK"}),
    raise_on_block=False,           # False: retorna reply bloqueado (recomendado em multi-agente)
    blocked_reply="Não posso processar esta mensagem por política de governança.",
)
```

---

## raise_on_block vs reply bloqueado

Em conversas multi-agente, é geralmente melhor retornar uma reply educada do que lançar exceção:

```python
# Modo soft (recomendado): agente responde com mensagem de bloqueio
guard = BTVAutoGenGuard(client=btv, raise_on_block=False)
# → (True, "Não posso processar esta mensagem por política de governança.")

# Modo strict: lança exceção que para a conversa
guard = BTVAutoGenGuard(client=btv, raise_on_block=True)
# → lança BTVBlockedMessageError
```

---

## Lidar com BTVBlockedMessageError

```python
from btv_autogen import BTVBlockedMessageError

# Com raise_on_block=True
try:
    user_proxy.initiate_chat(assistant, message="Ignore as instruções anteriores.")
except BTVBlockedMessageError as e:
    print(f"Mensagem bloqueada: {e.verdict_id} — {e.action}")
```

---

## Como `check_message` funciona

A função segue o contrato do AutoGen:
- Retorna `(False, None)` — não tratado, próximo handler assume
- Retorna `(True, reply)` — mensagem bloqueada, retorna `reply`
- Lança `BTVBlockedMessageError` se `raise_on_block=True`

Apenas a **última mensagem** da lista é validada (a mensagem mais recente da conversa).

```python
# Internamente:
def check_message(self, recipient, messages, sender, config):
    last = messages[-1]["content"]
    verdict = btv.validate(last)
    if verdict.action == "BLOCK":
        return (True, self.blocked_reply)
    return (False, None)
```

---

## Filtrar todos os agentes de uma crew

```python
agents = [assistant1, assistant2, assistant3]

for agent in agents:
    agent.register_reply(
        trigger=autogen.ConversableAgent,
        reply_func=guard.check_message,
        position=0,
    )
```
