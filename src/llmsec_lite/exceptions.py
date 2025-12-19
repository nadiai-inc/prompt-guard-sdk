"""Custom exceptions for LLMSEC LITE."""

from __future__ import annotations


class LLMSecError(Exception):
    """Base exception for LLMSEC LITE."""

    pass


class ConfigurationError(LLMSecError):
    """Configuration is invalid."""

    pass


class ModelNotFoundError(LLMSecError):
    """Required model not found and auto_download is False."""

    pass


class ModelLoadError(LLMSecError):
    """Failed to load model."""

    pass


class APIError(LLMSecError):
    """Error calling LLM API."""

    pass


class APIKeyMissingError(LLMSecError):
    """API key required but not provided."""

    pass


class ScanError(LLMSecError):
    """Error during scanning."""

    pass
