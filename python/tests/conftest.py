"""
Shared pytest fixtures and configuration.

Sets environment variables required by the application BEFORE any module
import occurs, so that singletons (JWT secret, DB paths) are initialised
with test-safe values.
"""
import os
import pytest

# ── Set env vars before any app module is imported ────────────────────────────
# BTV_JWT_SECRET must be >= 32 bytes for PyJWT HS256.
# The default "btv-dev-jwt-secret-NOT-FOR-PRODUCTION" is 38 chars but may not
# be visible to the app when the module-level constant is evaluated under pytest
# collection order. Setting it explicitly here guarantees it is always present.
os.environ.setdefault(
    "BTV_JWT_SECRET",
    "ci-test-jwt-secret-32bytes-padding!!",  # exactly 36 chars >= 32
)
os.environ.setdefault("BTV_ENV", "development")


@pytest.fixture(autouse=False)
def reset_evaluator_singleton():
    """Reset ComplianceEvaluator singleton between tests that need isolation."""
    import buildtovalue.api.routes.compliance_eval as ce_module
    ce_module._evaluator = None
    yield
    ce_module._evaluator = None
