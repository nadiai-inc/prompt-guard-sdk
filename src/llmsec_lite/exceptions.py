"""Custom exceptions for LLMSEC LITE."""

from __future__ import annotations


class LLMSecError(Exception):
    """Base exception for LLMSEC LITE."""

    pass


class ConfigurationError(LLMSecError):
    """Configuration is invalid."""

    pass


class ScanError(LLMSecError):
    """Error during scanning."""

    pass
