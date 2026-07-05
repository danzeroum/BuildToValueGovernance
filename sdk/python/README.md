# buildtovalue-sdk

SDK Python oficial do BuildToValue (BTV) — cliente para o gateway de
governança (porta 8080) e para a API Python (porta 8000).

```bash
pip install -e sdk/python/
```

```python
from btv_sdk import BTVClient

client = BTVClient("http://localhost:8080")
verdict = client.validate(input_text="Aprovar crédito para CPF 123.456.789-09")
print(verdict.action, verdict.blake3_hash)
```

> Nota de namespace: o pacote de import é `btv_sdk` (distribuição
> `buildtovalue-sdk`). O import `buildtovalue` pertence ao pacote da
> aplicação de governança (`python/`), que reexporta `BTVClient` e
> `AsyncBTVClient` quando este SDK está instalado — assim
> `from buildtovalue import BTVClient` também funciona com os dois
> pacotes presentes.
