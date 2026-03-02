"""Pytest fixtures for LLMSEC LITE tests."""

import pytest


@pytest.fixture
def sample_clean_text() -> str:
    """Sample clean text without any threats."""
    return "Tell me a joke about programming."


@pytest.fixture
def sample_secrets_text() -> str:
    """Sample text with secrets."""
    return "My API key is sk-1234567890abcdef1234567890abcdef1234567890abcdef"


@pytest.fixture
def sample_pii_text() -> str:
    """Sample text with PII."""
    return "My SSN is 123-45-6789 and my email is john@example.com"
