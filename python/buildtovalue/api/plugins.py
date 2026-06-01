"""BTV Gateway plugin contract and registry (Passo 14).

Lifecycle per plugin: register → validate_config → init → bind → execute → shutdown.

Thread-safe: all mutations hold an RLock. Fault-isolated: hook errors are
caught per-plugin and returned as a list of failed plugin IDs — they never
propagate to the caller or crash the application.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from threading import RLock
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PluginHookContext:
    """Immutable context passed to every hook invocation."""

    hook: str
    request_id: str
    payload: dict[str, Any] = field(default_factory=dict)


class PluginBase(ABC):
    """Abstract base for all BTV gateway plugins.

    Subclasses MUST implement ``plugin_id`` and ``version``.
    All hooks default to no-ops — override only the hooks you need.
    """

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """Unique plugin identifier (e.g. 'my-org/my-plugin:1.0')."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Semantic version string."""

    def validate_config(self) -> None:
        """Validate plugin configuration. Raise on error (blocks registration)."""

    def init(self) -> None:
        """Initialise resources. Raise on fatal error (blocks registration)."""

    def bind(self) -> frozenset[str]:
        """Return the hooks this plugin handles (used for logging/introspection)."""
        return frozenset({"pre_auth", "post_auth", "on_audit_event"})

    def shutdown(self) -> None:
        """Release resources. Called on unregister. Must not raise."""

    def pre_auth(self, ctx: PluginHookContext) -> None:
        """Called before auth validation. Raise to signal a hook error."""

    def post_auth(self, ctx: PluginHookContext) -> None:
        """Called after successful auth. Raise to signal a hook error."""

    def on_audit_event(self, ctx: PluginHookContext) -> None:
        """Called when an audit event is emitted. Raise to signal a hook error."""


class PluginRegistry:
    """Thread-safe registry with idempotent registration and fault isolation.

    ``register(plugin)`` is idempotent: a second call with the same
    ``plugin_id`` is silently dropped.

    ``run_hook(hook, ctx)`` calls every registered plugin that has bound
    to ``hook`` and returns a (possibly empty) list of ``plugin_id``s whose
    hook raised — errors are never re-raised.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        # Maps plugin_id → (plugin, bound_hooks)
        self._plugins: dict[str, tuple[PluginBase, frozenset[str]]] = {}

    def register(self, plugin: PluginBase) -> None:
        """Lifecycle: validate_config → init → bind → store.

        Idempotent: if ``plugin.plugin_id`` is already registered, returns
        immediately without re-initialising. Raises if validate_config() or
        init() fail — the plugin is NOT added to the registry in that case.
        """
        with self._lock:
            if plugin.plugin_id in self._plugins:
                return
            # Validate + init outside the lock would allow a race; keep inside.
            plugin.validate_config()
            plugin.init()
            hooks = plugin.bind()
            self._plugins[plugin.plugin_id] = (plugin, hooks)
            logger.debug("plugin registered: id=%s version=%s hooks=%s",
                         plugin.plugin_id, plugin.version, sorted(hooks))

    def unregister(self, plugin_id: str) -> None:
        """Remove a plugin and call shutdown() gracefully. No-op for unknown IDs."""
        with self._lock:
            entry = self._plugins.pop(plugin_id, None)
        if entry is None:
            return
        plugin, _ = entry
        try:
            plugin.shutdown()
        except Exception:
            logger.warning("plugin %s raised in shutdown(); ignoring", plugin_id)

    def plugin_ids(self) -> list[str]:
        with self._lock:
            return list(self._plugins.keys())

    def __len__(self) -> int:
        with self._lock:
            return len(self._plugins)

    def run_hook(self, hook: str, ctx: PluginHookContext) -> list[str]:
        """Execute ``hook`` on every registered plugin that has bound to it.

        Returns the list of ``plugin_id``s whose hook raised an exception.
        Errors are isolated — they never propagate; remaining plugins still run.
        """
        with self._lock:
            targets = [
                (pid, plugin)
                for pid, (plugin, hooks) in self._plugins.items()
                if hook in hooks
            ]

        failed: list[str] = []
        for pid, plugin in targets:
            try:
                method = getattr(plugin, hook, None)
                if method is not None:
                    method(ctx)
            except Exception as exc:
                logger.warning("plugin %s raised in hook %s: %s", pid, hook, exc)
                failed.append(pid)
        return failed
