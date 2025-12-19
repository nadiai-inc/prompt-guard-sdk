"""LLMSEC LITE - Enterprise LLM Security, Lightweight.

A lightweight Python SDK providing 6 guard rails for LLM security:

1. Prompt Injection Detection (ONNX)
2. Secrets Detection (Regex)
3. PII Protection (Regex + LLM)
4. Toxicity Filter (ONNX)
5. Hallucination Detection (LLM)
6. Code Injection Detection (Regex)

Example:
    >>> from llmsec_lite import TrustGuard
    >>> guard = TrustGuard()
    >>> result = guard.scan_input("user prompt")
    >>> if result.blocked:
    ...     print(result.reasons)

For full mode with hallucination detection:
    >>> guard = TrustGuard(api_key="sk-...", mode="full")
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
    LLMConfig,
    ScannersConfig,
    ScannerConfig,
    PIIConfig,
    Mode,
    RedactionStyle,
    Sensitivity,
)
from llmsec_lite.exceptions import (
    APIError,
    APIKeyMissingError,
    ConfigurationError,
    LLMSecError,
    ModelLoadError,
    ModelNotFoundError,
    ScanError,
)


async def download_models(cache_dir: str = "~/.llmsec-lite", force: bool = False) -> dict:
    """Download all ONNX models required by the SDK.

    Models are downloaded from HuggingFace and cached locally.

    Args:
        cache_dir: Directory to cache models (default: ~/.llmsec-lite)
        force: Force re-download even if models exist

    Returns:
        Dictionary with download status for each model

    Example:
        >>> import asyncio
        >>> from llmsec_lite import download_models
        >>> result = asyncio.run(download_models())
        >>> print(result)
        {'injection': '/path/to/model.onnx', 'toxicity': '/path/to/model.onnx', ...}
    """
    from llmsec_lite.models.downloader import download_model, MODEL_REGISTRY

    results = {}
    for model_id in MODEL_REGISTRY:
        try:
            path = await download_model(model_id, cache_dir, force)
            results[model_id] = str(path)
        except Exception as e:
            results[model_id] = f"Error: {e}"

    return results


def download_models_sync(cache_dir: str = "~/.llmsec-lite", force: bool = False) -> dict:
    """Synchronous version of download_models.

    Example:
        >>> from llmsec_lite import download_models_sync
        >>> result = download_models_sync()
    """
    import asyncio
    return asyncio.run(download_models(cache_dir, force))


__version__ = "1.0.0"
__author__ = "NadiAI"
__email__ = "support@nadiai.com"

__all__ = [
    # Main class
    "TrustGuard",
    # Model download
    "download_models",
    "download_models_sync",
    # Result types
    "ScanResult",
    "FullScanResult",
    "CheckResult",
    "Finding",
    "Severity",
    # Configuration (for database integration)
    "LLMSecLiteConfig",
    "LLMConfig",
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
    "ModelNotFoundError",
    "ModelLoadError",
    "APIError",
    "APIKeyMissingError",
    "ScanError",
    # Version
    "__version__",
]
