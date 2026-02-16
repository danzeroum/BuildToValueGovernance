use buildtovalue_kernel::gatekeeper::Gatekeeper;
use std::sync::Mutex;

pub struct AppState {
    pub gatekeeper: Mutex<Gatekeeper>,
    pub http_client: reqwest::Client,
    pub start_time: std::time::Instant,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            gatekeeper: Mutex::new(Gatekeeper::new()),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(500))
                .build()
                .expect("Failed to create HTTP client"),
            start_time: std::time::Instant::now(),
        }
    }
}