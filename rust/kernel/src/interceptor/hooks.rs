//! Interceptor Hooks v1.7.0 — Pre/Post processing chain (ADR-015)
//! Chain of Responsibility: fail-secure (hook failure → BLOCK).

// ---------------------------------------------------------------------
// INTERCEPT ACTION
// ---------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterceptAction {
    Continue,
    Modify(String),
    Block(String),
}

#[derive(Debug, Clone)]
pub struct InterceptResult {
    pub action: InterceptAction,
    pub hook_name: String,
}

// ---------------------------------------------------------------------
// TRAITS
// ---------------------------------------------------------------------
pub trait RequestInterceptor: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u32;
    fn intercept_request(&self, input: &str) -> InterceptResult;
}

pub trait ResponseInterceptor: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u32;
    fn intercept_response(&self, output: &str) -> InterceptResult;
}

// ---------------------------------------------------------------------
// CHAIN
// ---------------------------------------------------------------------
pub struct InterceptorChain {
    request_hooks: Vec<Box<dyn RequestInterceptor>>,
    response_hooks: Vec<Box<dyn ResponseInterceptor>>,
}

impl InterceptorChain {
    pub fn new() -> Self {
        Self {
            request_hooks: Vec::new(),
            response_hooks: Vec::new(),
        }
    }

    pub fn add_request_hook(&mut self, hook: Box<dyn RequestInterceptor>) {
        self.request_hooks.push(hook);
        self.request_hooks.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    pub fn add_response_hook(&mut self, hook: Box<dyn ResponseInterceptor>) {
        self.response_hooks.push(hook);
        self.response_hooks.sort_by(|a, b| b.priority().cmp(&a.priority()));
    }

    /// Run all request interceptors. Fail-secure: any error → Block.
    pub fn run_request(&self, input: &str) -> (InterceptAction, String) {
        let mut current = input.to_string();

        for hook in &self.request_hooks {
            let result = std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| hook.intercept_request(&current))
            );

            match result {
                Ok(r) => match r.action {
                    InterceptAction::Continue => {}
                    InterceptAction::Modify(new) => { current = new; }
                    InterceptAction::Block(reason) => {
                        return (InterceptAction::Block(reason), current);
                    }
                },
                Err(_) => {
                    log::error!("Request hook '{}' panicked — fail-secure BLOCK", hook.name());
                    return (
                        InterceptAction::Block(format!("Hook '{}' failed", hook.name())),
                        current,
                    );
                }
            }
        }

        (InterceptAction::Continue, current)
    }

    /// Run all response interceptors. Fail-secure: any error → Block.
    pub fn run_response(&self, output: &str) -> (InterceptAction, String) {
        let mut current = output.to_string();

        for hook in &self.response_hooks {
            let result = std::panic::catch_unwind(
                std::panic::AssertUnwindSafe(|| hook.intercept_response(&current))
            );

            match result {
                Ok(r) => match r.action {
                    InterceptAction::Continue => {}
                    InterceptAction::Modify(new) => { current = new; }
                    InterceptAction::Block(reason) => {
                        return (InterceptAction::Block(reason), current);
                    }
                },
                Err(_) => {
                    log::error!("Response hook '{}' panicked — fail-secure BLOCK", hook.name());
                    return (
                        InterceptAction::Block(format!("Hook '{}' failed", hook.name())),
                        current,
                    );
                }
            }
        }

        (InterceptAction::Continue, current)
    }

    pub fn request_hook_count(&self) -> usize { self.request_hooks.len() }
    pub fn response_hook_count(&self) -> usize { self.response_hooks.len() }
}

impl Default for InterceptorChain {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------
// BUILT-IN: MaxLengthHook (example)
// ---------------------------------------------------------------------
pub struct MaxLengthHook {
    max_len: usize,
}

impl MaxLengthHook {
    pub fn new(max_len: usize) -> Self { Self { max_len } }
}

impl RequestInterceptor for MaxLengthHook {
    fn name(&self) -> &'static str { "max_length" }
    fn priority(&self) -> u32 { 100 }
    fn intercept_request(&self, input: &str) -> InterceptResult {
        if input.len() > self.max_len {
            InterceptResult {
                action: InterceptAction::Block(
                    format!("Input exceeds max length: {} > {}", input.len(), self.max_len)
                ),
                hook_name: "max_length".to_string(),
            }
        } else {
            InterceptResult { action: InterceptAction::Continue, hook_name: "max_length".to_string() }
        }
    }
}

// ---------------------------------------------------------------------
// BUILT-IN: TrimHook (example)
// ---------------------------------------------------------------------
pub struct TrimHook;

impl RequestInterceptor for TrimHook {
    fn name(&self) -> &'static str { "trim" }
    fn priority(&self) -> u32 { 200 } // runs before max_length
    fn intercept_request(&self, input: &str) -> InterceptResult {
        let trimmed = input.trim();
        if trimmed.len() != input.len() {
            InterceptResult {
                action: InterceptAction::Modify(trimmed.to_string()),
                hook_name: "trim".to_string(),
            }
        } else {
            InterceptResult { action: InterceptAction::Continue, hook_name: "trim".to_string() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain_continues() {
        let chain = InterceptorChain::new();
        let (action, output) = chain.run_request("hello");
        assert_eq!(action, InterceptAction::Continue);
        assert_eq!(output, "hello");
    }

    #[test]
    fn test_trim_hook_modifies() {
        let mut chain = InterceptorChain::new();
        chain.add_request_hook(Box::new(TrimHook));
        let (action, output) = chain.run_request("  hello  ");
        assert_eq!(action, InterceptAction::Continue);
        assert_eq!(output, "hello");
    }

    #[test]
    fn test_max_length_blocks() {
        let mut chain = InterceptorChain::new();
        chain.add_request_hook(Box::new(MaxLengthHook::new(10)));
        let (action, _) = chain.run_request("this is way too long input");
        assert!(matches!(action, InterceptAction::Block(_)));
    }

    #[test]
    fn test_chain_ordering_by_priority() {
        let mut chain = InterceptorChain::new();
        chain.add_request_hook(Box::new(MaxLengthHook::new(5)));   // priority 100
        chain.add_request_hook(Box::new(TrimHook));                 // priority 200
        // Trim runs first (higher priority), then max_length
        let (action, _) = chain.run_request("  hi  "); // trims to "hi" (len 2)
        assert_eq!(action, InterceptAction::Continue); // 2 < 5, passes
    }

    #[test]
    fn test_block_stops_chain() {
        let mut chain = InterceptorChain::new();
        chain.add_request_hook(Box::new(MaxLengthHook::new(3)));
        chain.add_request_hook(Box::new(TrimHook));
        // "  abcdef  " → trim → "abcdef" (6 > 3) → BLOCK
        let (action, _) = chain.run_request("  abcdef  ");
        assert!(matches!(action, InterceptAction::Block(_)));
    }

    #[test]
    fn test_response_chain() {
        let chain = InterceptorChain::new();
        let (action, output) = chain.run_response("response text");
        assert_eq!(action, InterceptAction::Continue);
        assert_eq!(output, "response text");
    }

    #[test]
    fn test_hook_counts() {
        let mut chain = InterceptorChain::new();
        chain.add_request_hook(Box::new(TrimHook));
        chain.add_request_hook(Box::new(MaxLengthHook::new(100)));
        assert_eq!(chain.request_hook_count(), 2);
        assert_eq!(chain.response_hook_count(), 0);
    }
}