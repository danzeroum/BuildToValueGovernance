"""Security observability counters + HTTP latency histogram (Passo 13).

These are distinct from the governance-domain metrics in
buildtovalue/observability/metrics.py (which track decisions, trust, appeals).
These metrics track the API gateway layer: auth failures, rate-limit
responses, and per-request latency — the security-operations signals that
need to be observable ponta-a-ponta.
"""
from prometheus_client import Counter, Histogram

BTV_AUTH_FAILURES_TOTAL = Counter(
    "btv_auth_failures_total",
    "Total HTTP 401 Unauthorized responses from the Python API layer"
    " (invalid or missing API key / JWT).",
)

BTV_RATE_LIMIT_EXCEEDED_TOTAL = Counter(
    "btv_rate_limit_exceeded_total",
    "Total HTTP 429 Too Many Requests responses from the Python API layer.",
)

BTV_HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "btv_http_request_duration_seconds",
    "HTTP request duration in seconds, labelled by method, path, and status.",
    ["method", "path", "status"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)
