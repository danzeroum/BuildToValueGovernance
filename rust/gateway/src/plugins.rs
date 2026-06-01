//! BTV Gateway plugin contract and registry (Passo 14).
// Public extension-point API: items here are designed to be implemented and
// called by downstream plugin crates, not the gateway binary itself.
#![allow(dead_code)]
//!
//! Lifecycle per plugin: register → execute(hooks) → (implicit shutdown on drop).
//!
//! `GatewayPlugin` is **synchronous** by design — same rationale as
//! `EthicsValidator` in the kernel: zero heap allocation in the hot path.
//!
//! `GatewayPluginRegistry` is **thread-safe** (interior `RwLock`) and
//! **fault-isolated**: a hook returning `Err` is logged and collected in the
//! failed list; remaining plugins always execute.
//!
//! Registration is **idempotent**: a second `register()` with the same
//! `plugin_id()` returns `false` and leaves the registry unchanged.

/// Context passed to every hook invocation.
pub struct HookContext {
    /// Name of the hook being fired (e.g. `"pre_auth"`).
    pub hook: &'static str,
    /// Request correlation ID (UUID4 from `X-BTV-Request-ID`).
    pub request_id: String,
}

/// Error returned by a plugin hook.
#[derive(Debug, Clone)]
pub struct PluginError {
    pub plugin_id: &'static str,
    pub message: &'static str,
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "plugin '{}' hook failed: {}", self.plugin_id, self.message)
    }
}

impl std::error::Error for PluginError {}

/// Gateway plugin contract.  Implement this trait and register with
/// `GatewayPluginRegistry::register()` to extend the BTV gateway without
/// modifying core code.
///
/// # Invariants
/// - **No panic** — return `Err(PluginError)` on any failure.
/// - **Síncrono** — hooks run synchronously in the request hot path.
/// - **`plugin_id` unique** — duplicate IDs are rejected idempotently.
pub trait GatewayPlugin: Send + Sync {
    /// Unique plugin identifier. Must be stable across restarts.
    fn plugin_id(&self) -> &'static str;
    /// Semantic version string.
    fn version(&self) -> &'static str;

    /// Hook called before auth validation.
    fn on_pre_auth(&self, ctx: &HookContext) -> Result<(), PluginError>;
    /// Hook called after successful auth.
    fn on_post_auth(&self, ctx: &HookContext) -> Result<(), PluginError>;
    /// Hook called when an audit event is emitted.
    fn on_audit_event(&self, ctx: &HookContext) -> Result<(), PluginError>;
}

/// Thread-safe plugin registry with idempotent registration and fault isolation.
pub struct GatewayPluginRegistry {
    plugins: std::sync::RwLock<Vec<Box<dyn GatewayPlugin>>>,
}

impl Default for GatewayPluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayPluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// Register a plugin. Returns `true` if added, `false` if `plugin_id()`
    /// was already registered (idempotent — registry unchanged on `false`).
    pub fn register(&self, plugin: Box<dyn GatewayPlugin>) -> bool {
        let mut guard = self
            .plugins
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if guard.iter().any(|p| p.plugin_id() == plugin.plugin_id()) {
            return false;
        }
        tracing::debug!(
            plugin_id = plugin.plugin_id(),
            version = plugin.version(),
            "gateway plugin registered"
        );
        guard.push(plugin);
        true
    }

    pub fn len(&self) -> usize {
        self.plugins
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Run `on_pre_auth` on all plugins. Returns IDs of plugins that returned `Err`.
    pub fn run_pre_auth(&self, ctx: &HookContext) -> Vec<&'static str> {
        self.run_hook(ctx, |p, c| p.on_pre_auth(c))
    }

    /// Run `on_post_auth` on all plugins. Returns IDs of plugins that returned `Err`.
    pub fn run_post_auth(&self, ctx: &HookContext) -> Vec<&'static str> {
        self.run_hook(ctx, |p, c| p.on_post_auth(c))
    }

    /// Run `on_audit_event` on all plugins. Returns IDs of plugins that returned `Err`.
    pub fn run_audit_event(&self, ctx: &HookContext) -> Vec<&'static str> {
        self.run_hook(ctx, |p, c| p.on_audit_event(c))
    }

    fn run_hook<F>(&self, ctx: &HookContext, call: F) -> Vec<&'static str>
    where
        F: Fn(&dyn GatewayPlugin, &HookContext) -> Result<(), PluginError>,
    {
        let guard = self
            .plugins
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut failed: Vec<&'static str> = Vec::new();
        for plugin in guard.iter() {
            if let Err(ref e) = call(plugin.as_ref(), ctx) {
                tracing::warn!(
                    plugin_id = plugin.plugin_id(),
                    hook = ctx.hook,
                    error = %e,
                    "plugin hook error (isolated)"
                );
                failed.push(plugin.plugin_id());
            }
        }
        failed
    }
}
