"""Shared fixtures for scenario simulation tests."""
import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "scenario: Scenario simulation tests")
