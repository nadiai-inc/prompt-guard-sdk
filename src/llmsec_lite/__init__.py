"""LLMSEC LITE - Enterprise LLM Security, Lightweight.

A lightweight Python SDK providing 2 guard rails for LLM security:

1. Secrets Detection (Regex)
2. PII Protection (Regex)

Example:
    >>> from llmsec_lite import TrustGuard
    >>> guard = TrustGuard()
    >>> result = guard.scan_input("user prompt")
    >>> if result.blocked:
    ...     print(result.reasons)
"""

from llmsec_lite.guard import TrustGuard
from llmsec_lite.schemas.results import (
    CheckResult,
    Finding,
    FullScanResult,
    ScanResult,
    Severity,
)
from llmsec_lite.schemas.config import (
    GuardConfig,
    LLMSecLiteConfig,
    ScannersConfig,
    ScannerConfig,
    PIIConfig,
    Mode,
    RedactionStyle,
    Sensitivity,
)
from llmsec_lite.exceptions import (
    ConfigurationError,
    LLMSecError,
    ScanError,
)


__version__ = "2.0.0"
__author__ = "NadiAI"
__email__ = "support@nadiai.com"

__all__ = [
    # Main class
    "TrustGuard",
    # Result types
    "ScanResult",
    "FullScanResult",
    "CheckResult",
    "Finding",
    "Severity",
    # Configuration (for database integration)
    "LLMSecLiteConfig",
    "ScannersConfig",
    "ScannerConfig",
    "PIIConfig",
    "GuardConfig",
    "Mode",
    "Sensitivity",
    "RedactionStyle",
    # Exceptions
    "LLMSecError",
    "ConfigurationError",
    "ScanError",
    # Version
    "__version__",
]
