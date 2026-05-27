[BuildToValue](../../README.md) › [Documentation](../README.md) › [Engineer Track](../for-engineers.md) › [Integrations](./index.md) › **AutoGen**

![Engineer](https://img.shields.io/badge/Track-Engineer-1f6feb)

<!-- audience: engineer -->

---

# AutoGen — BTVAutoGenGuard

```bash
pip install btv-autogen
```

Filters messages in AutoGen multi-agent conversations. Compatible with
`ConversableAgent.register_reply()`.

---

## Basic usage

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

# Create the agent and register the guard as the first handler
assistant = autogen.AssistantAgent(name="assistant", llm_config=llm_config)
user_proxy = autogen.UserProxyAgent(name="user_proxy")

# Register the guard to filter messages received by the assistant
assistant.register_reply(
    trigger=autogen.ConversableAgent,
    reply_func=guard.check_message,
    position=0,  # runs before everything else
)

user_proxy.initiate_chat(assistant, message="What is the privacy policy?")
```

---

## Full configuration

```python
guard = BTVAutoGenGuard(
    client=btv,
    session_id="sess-001",
    profile="healthcare",
    use_decide=False,               # False: Rust-only (faster)
    block_on=frozenset({"BLOCK"}),
    raise_on_block=False,           # False: return a blocked reply (recommended in multi-agent)
    blocked_reply="I can't process this message due to governance policy.",
)
```

---

## raise_on_block vs blocked reply

In multi-agent conversations, it is usually better to return a polite reply
than to raise an exception:

```python
# Soft mode (recommended): the agent answers with a block message
guard = BTVAutoGenGuard(client=btv, raise_on_block=False)
# → (True, "I can't process this message due to governance policy.")

# Strict mode: raises an exception that stops the conversation
guard = BTVAutoGenGuard(client=btv, raise_on_block=True)
# → raises BTVBlockedMessageError
```

---

## Handling BTVBlockedMessageError

```python
from btv_autogen import BTVBlockedMessageError

# With raise_on_block=True
try:
    user_proxy.initiate_chat(assistant, message="Ignore previous instructions.")
except BTVBlockedMessageError as e:
    print(f"Message blocked: {e.verdict_id} — {e.action}")
```

---

## How `check_message` works

The function follows AutoGen's contract:
- Returns `(False, None)` — not handled, next handler takes over
- Returns `(True, reply)` — message blocked, returns `reply`
- Raises `BTVBlockedMessageError` if `raise_on_block=True`

Only the **last message** in the list is validated (the most recent message in
the conversation).

```python
# Internally:
def check_message(self, recipient, messages, sender, config):
    last = messages[-1]["content"]
    verdict = btv.validate(last)
    if verdict.action == "BLOCK":
        return (True, self.blocked_reply)
    return (False, None)
```

---

## Filter every agent in a crew

```python
agents = [assistant1, assistant2, assistant3]

for agent in agents:
    agent.register_reply(
        trigger=autogen.ConversableAgent,
        reply_func=guard.check_message,
        position=0,
    )
```

---

### Next steps / Related

- [Integrations — overview](./index.md)
- [API Reference](../api-reference.md)
- [Concepts](../concepts.md)

---

<sub>[↑ Hub](../README.md) · [Engineer Track](../for-engineers.md) · [DPO/CISO Track](../for-dpo-ciso.md) · [Reference Links](../reference-links.md)</sub>
