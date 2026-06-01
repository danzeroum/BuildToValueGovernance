"""Shared setup for system (E2E in-process) tests — Passo 15.

Must run before any app-module import so that singletons (JWT_SECRET,
rate limiter, ADMIN_PASSWORD) are initialised with test-safe values.
Uses the SAME constants as tests/conftest.py so the suite works both
standalone and when run as part of the full test collection.
"""
import os

os.environ.setdefault("BTV_ADMIN_PASSWORD", "ci-test-admin-password-2026")
os.environ.setdefault("BTV_ENV", "development")
os.environ.setdefault("BTV_JWT_SECRET", "ci-test-jwt-secret-32bytes-padding!!")
