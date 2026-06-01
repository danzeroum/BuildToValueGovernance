"""RED tests — Passo 14: Plugin Contract & Registry.

Verifies the PluginBase/PluginRegistry contract without touching the core:
  1. Registry starts empty.
  2. Registering a plugin stores it (plugin_ids lists its ID).
  3. Idempotent registration — same plugin_id a second time is a no-op.
  4. validate_config() failure → plugin NOT added to registry.
  5. init() failure → plugin NOT added to registry.
  6. run_hook("pre_auth", ctx) invokes the plugin's pre_auth() method.
  7. run_hook("post_auth", ctx) invokes the plugin's post_auth() method.
  8. run_hook("on_audit_event", ctx) invokes the plugin's on_audit_event().
  9. Plugin hook raising does NOT propagate — error is isolated.
 10. Fault-isolated: remaining plugins still run after one plugin fails.
 11. shutdown() is called on unregister().
 12. PluginHookContext carries hook name, request_id, and payload.
"""
import pytest

from buildtovalue.api.plugins import PluginBase, PluginHookContext, PluginRegistry

pytestmark = pytest.mark.security


# ──────────────────────────────────── helpers ────────────────────────────────


class _CallLog:
    def __init__(self) -> None:
        self.calls: list[str] = []


class _OkPlugin(PluginBase):
    def __init__(self, pid: str = "ok-plugin", log: _CallLog | None = None) -> None:
        self._pid = pid
        self._log = log or _CallLog()

    @property
    def plugin_id(self) -> str:
        return self._pid

    @property
    def version(self) -> str:
        return "1.0.0"

    def init(self) -> None:
        self._log.calls.append("init")

    def shutdown(self) -> None:
        self._log.calls.append("shutdown")

    def pre_auth(self, ctx: PluginHookContext) -> None:
        self._log.calls.append(f"pre_auth:{ctx.request_id}")

    def post_auth(self, ctx: PluginHookContext) -> None:
        self._log.calls.append(f"post_auth:{ctx.request_id}")

    def on_audit_event(self, ctx: PluginHookContext) -> None:
        self._log.calls.append(f"on_audit_event:{ctx.request_id}")


class _ValidateFailPlugin(PluginBase):
    @property
    def plugin_id(self) -> str:
        return "validate-fail"

    @property
    def version(self) -> str:
        return "0.1.0"

    def validate_config(self) -> None:
        raise ValueError("bad config")


class _InitFailPlugin(PluginBase):
    @property
    def plugin_id(self) -> str:
        return "init-fail"

    @property
    def version(self) -> str:
        return "0.1.0"

    def init(self) -> None:
        raise RuntimeError("init exploded")


class _HookFailPlugin(PluginBase):
    """Plugin whose hooks always raise — used to test fault isolation."""

    def __init__(self) -> None:
        self.post_auth_called = False

    @property
    def plugin_id(self) -> str:
        return "hook-fail"

    @property
    def version(self) -> str:
        return "1.0.0"

    def pre_auth(self, ctx: PluginHookContext) -> None:
        raise RuntimeError("pre_auth exploded")

    def post_auth(self, ctx: PluginHookContext) -> None:
        self.post_auth_called = True


# ──────────────────────────────── fixtures ───────────────────────────────────


@pytest.fixture
def registry() -> PluginRegistry:
    return PluginRegistry()


@pytest.fixture
def ctx() -> PluginHookContext:
    return PluginHookContext(hook="pre_auth", request_id="req-001", payload={"k": "v"})


# ──────────────────────────────── tests ──────────────────────────────────────


class TestRegistryLifecycle:
    def test_registry_starts_empty(self, registry: PluginRegistry) -> None:
        assert len(registry) == 0
        assert registry.plugin_ids() == []

    def test_register_adds_plugin(self, registry: PluginRegistry) -> None:
        registry.register(_OkPlugin())
        assert len(registry) == 1
        assert "ok-plugin" in registry.plugin_ids()

    def test_register_calls_init(self, registry: PluginRegistry) -> None:
        log = _CallLog()
        registry.register(_OkPlugin(log=log))
        assert "init" in log.calls

    def test_register_is_idempotent(self, registry: PluginRegistry) -> None:
        registry.register(_OkPlugin())
        registry.register(_OkPlugin())  # same plugin_id
        assert len(registry) == 1, "duplicate plugin_id must not be added twice"

    def test_validate_config_failure_blocks_registration(
        self, registry: PluginRegistry
    ) -> None:
        with pytest.raises(Exception):
            registry.register(_ValidateFailPlugin())
        assert len(registry) == 0, "failed plugin must not appear in registry"

    def test_init_failure_blocks_registration(self, registry: PluginRegistry) -> None:
        with pytest.raises(Exception):
            registry.register(_InitFailPlugin())
        assert len(registry) == 0, "failed plugin must not appear in registry"

    def test_unregister_calls_shutdown(self, registry: PluginRegistry) -> None:
        log = _CallLog()
        plugin = _OkPlugin(log=log)
        registry.register(plugin)
        registry.unregister("ok-plugin")
        assert "shutdown" in log.calls

    def test_unregister_removes_plugin(self, registry: PluginRegistry) -> None:
        registry.register(_OkPlugin())
        registry.unregister("ok-plugin")
        assert len(registry) == 0
        assert "ok-plugin" not in registry.plugin_ids()

    def test_unregister_unknown_id_is_noop(self, registry: PluginRegistry) -> None:
        registry.unregister("nonexistent")  # must not raise


class TestHookContext:
    def test_context_carries_hook_name(self, ctx: PluginHookContext) -> None:
        assert ctx.hook == "pre_auth"

    def test_context_carries_request_id(self, ctx: PluginHookContext) -> None:
        assert ctx.request_id == "req-001"

    def test_context_carries_payload(self, ctx: PluginHookContext) -> None:
        assert ctx.payload == {"k": "v"}


class TestRunHook:
    def test_pre_auth_invokes_plugin(self, registry: PluginRegistry) -> None:
        log = _CallLog()
        registry.register(_OkPlugin(log=log))
        ctx = PluginHookContext(hook="pre_auth", request_id="r1")
        registry.run_hook("pre_auth", ctx)
        assert any("pre_auth:r1" in c for c in log.calls)

    def test_post_auth_invokes_plugin(self, registry: PluginRegistry) -> None:
        log = _CallLog()
        registry.register(_OkPlugin(log=log))
        ctx = PluginHookContext(hook="post_auth", request_id="r2")
        registry.run_hook("post_auth", ctx)
        assert any("post_auth:r2" in c for c in log.calls)

    def test_on_audit_event_invokes_plugin(self, registry: PluginRegistry) -> None:
        log = _CallLog()
        registry.register(_OkPlugin(log=log))
        ctx = PluginHookContext(hook="on_audit_event", request_id="r3")
        registry.run_hook("on_audit_event", ctx)
        assert any("on_audit_event:r3" in c for c in log.calls)

    def test_hook_failure_does_not_propagate(self, registry: PluginRegistry) -> None:
        registry.register(_HookFailPlugin())
        ctx = PluginHookContext(hook="pre_auth", request_id="r4")
        failed = registry.run_hook("pre_auth", ctx)  # must not raise
        assert "hook-fail" in failed

    def test_fault_isolated_other_plugins_still_run(
        self, registry: PluginRegistry
    ) -> None:
        fail_plugin = _HookFailPlugin()
        ok_log = _CallLog()
        ok_plugin = _OkPlugin(pid="ok-second", log=ok_log)
        registry.register(fail_plugin)
        registry.register(ok_plugin)
        ctx = PluginHookContext(hook="pre_auth", request_id="r5")
        failed = registry.run_hook("pre_auth", ctx)
        assert "hook-fail" in failed, "failing plugin must appear in failed list"
        assert any("pre_auth:r5" in c for c in ok_log.calls), (
            "ok plugin must still run after the failing plugin"
        )

    def test_run_hook_returns_empty_list_on_success(
        self, registry: PluginRegistry
    ) -> None:
        registry.register(_OkPlugin())
        ctx = PluginHookContext(hook="pre_auth", request_id="r6")
        failed = registry.run_hook("pre_auth", ctx)
        assert failed == [], "no failures means empty failed list"
