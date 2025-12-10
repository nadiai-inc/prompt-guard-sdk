"""
NadiAI Prompt Guard SDK
=======================
Local LLM security scanning with ONNX models.

Provides fast, offline scanning for:
- Prompt Injection attacks
- Harmful/Toxic content
- Basic PII detection

Models are downloaded once on first use and cached locally.
All subsequent scans run 100% locally with no network calls.

Quick Start:
    # Option 1: Download models on first scan (automatic)
    from nadiai_prompt_guard import PromptGuard

    guard = PromptGuard()
    result = guard.scan("Your prompt here")

    if result.blocked:
        print(f"Blocked: {result.threats}")

    # Option 2: Pre-download models for offline use
    from nadiai_prompt_guard import download_models
    download_models()  # Run once to download models (~700MB)
"""

from .scanner import (
    PromptGuard,
    ScanResult,
    ThreatInfo,
    RiskLevel,
    download_models,
    models_downloaded,
)

__version__ = "0.1.0"
__all__ = [
    "PromptGuard",
    "ScanResult",
    "ThreatInfo",
    "RiskLevel",
    "download_models",
    "models_downloaded",
]
