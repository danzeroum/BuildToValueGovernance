__version__ = "0.1.0a1"

# Reexport lazy do cliente SDK (distribuição buildtovalue-sdk, import btv_sdk).
# Permite `from buildtovalue import BTVClient` quando o SDK está instalado
# junto — a conveniência que o README prometia — sem adicionar dependência
# obrigatória nem custo de import para quem usa só a API de governança.
_SDK_EXPORTS = {
    "BTVClient", "AsyncBTVClient", "BTVSession",
    "VerdictAction", "Verdict", "ValidateVerdict",
    "BTVError", "BTVAuthError", "BTVBlockedError",
}


def __getattr__(name: str):
    if name in _SDK_EXPORTS:
        try:
            import btv_sdk
        except ImportError as exc:
            raise ImportError(
                f"'{name}' é o cliente SDK — instale a distribuição "
                f"buildtovalue-sdk (pip install -e sdk/python/) ou importe "
                f"diretamente de btv_sdk."
            ) from exc
        return getattr(btv_sdk, name)
    raise AttributeError(f"module 'buildtovalue' has no attribute '{name}'")
