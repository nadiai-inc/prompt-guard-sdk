"""
NadiAI Prompt Guard Scanner
===========================
Main scanner class for local LLM security scanning.

Uses ONNX Runtime for fast, offline inference with pre-trained models:
- Prompt Injection Detection (DeBERTa)
- Harmful Content Detection (BERT toxicity)
- Basic PII Detection (regex patterns)

Models are downloaded once on first use and cached locally for offline operation.
All subsequent scans run 100% locally with no network calls.

Usage:
    # First time: downloads models (~700MB)
    guard = PromptGuard()

    # All subsequent uses: runs locally
    result = guard.scan("Your prompt here")
"""

import re
import time
import logging
import os
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# Lazy imports for ONNX Runtime
_ONNX_AVAILABLE = None
_ORTModelForSequenceClassification = None
_AutoTokenizer = None

logger = logging.getLogger(__name__)

# Default model cache directory - can be overridden via environment variable
DEFAULT_CACHE_DIR = os.environ.get(
    "NADIAI_MODEL_CACHE",
    os.path.expanduser("~/.nadiai_prompt_guard/models")
)


def _check_onnx_available():
    """Lazy check for ONNX availability"""
    global _ONNX_AVAILABLE, _ORTModelForSequenceClassification, _AutoTokenizer

    if _ONNX_AVAILABLE is not None:
        return _ONNX_AVAILABLE

    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import AutoTokenizer
        import torch

        _ORTModelForSequenceClassification = ORTModelForSequenceClassification
        _AutoTokenizer = AutoTokenizer
        _ONNX_AVAILABLE = True
        return True
    except ImportError as e:
        logger.warning(f"ONNX Runtime not available: {e}")
        logger.warning("Install with: pip install optimum[onnxruntime] transformers torch")
        _ONNX_AVAILABLE = False
        return False


def models_downloaded(cache_dir: str = None) -> bool:
    """
    Check if models have been downloaded to the local cache.

    Args:
        cache_dir: Optional custom cache directory. Uses default if not specified.

    Returns:
        True if models exist in cache, False otherwise
    """
    cache_path = Path(cache_dir or DEFAULT_CACHE_DIR).expanduser()

    # Check for HuggingFace hub cache structure
    hub_cache = Path.home() / ".cache" / "huggingface" / "hub"

    injection_model = hub_cache / "models--protectai--deberta-v3-base-prompt-injection-v2"
    toxic_model = hub_cache / "models--martin-ha--toxic-comment-model"

    return injection_model.exists() and toxic_model.exists()


def _check_model_exported(model_name: str) -> bool:
    """Check if a model has already been exported to ONNX format in HuggingFace cache."""
    hub_cache = Path.home() / ".cache" / "huggingface" / "hub"
    cache_name = f"models--{model_name.replace('/', '--')}"
    model_cache = hub_cache / cache_name

    if not model_cache.exists():
        return False

    snapshots_dir = model_cache / "snapshots"
    if snapshots_dir.exists():
        for snapshot in snapshots_dir.iterdir():
            if snapshot.is_dir():
                onnx_files = list(snapshot.glob("*.onnx"))
                if onnx_files:
                    return True
    return False


def download_models(cache_dir: str = None, verbose: bool = True) -> bool:
    """
    Pre-download models to local cache for offline use.

    This function downloads all required ML models to the local HuggingFace cache.
    After running this once, all subsequent scans will run 100% locally with no
    network calls required.

    Args:
        cache_dir: Optional custom cache directory. Uses default if not specified.
        verbose: Print progress messages

    Returns:
        True if models downloaded successfully, False otherwise

    Example:
        >>> from nadiai_prompt_guard import download_models
        >>> download_models()  # Downloads ~700MB of models
        Downloading prompt injection model...
        Downloading harmful content model...
        Models downloaded successfully!
    """
    if not _check_onnx_available():
        if verbose:
            print("ERROR: ONNX Runtime not available. Install with:")
            print("  pip install optimum[onnxruntime] transformers torch")
        return False

    cache_path = Path(cache_dir or DEFAULT_CACHE_DIR).expanduser()
    cache_path.mkdir(parents=True, exist_ok=True)

    try:
        # Download prompt injection model (has pre-exported ONNX)
        model_name = "protectai/deberta-v3-base-prompt-injection-v2"
        if verbose:
            print("Downloading prompt injection model (DeBERTa, pre-exported ONNX)...")

        _ORTModelForSequenceClassification.from_pretrained(
            model_name,
            export=False,
            subfolder="onnx",
            provider="CPUExecutionProvider"
        )
        _AutoTokenizer.from_pretrained(model_name, subfolder="onnx")

        if verbose:
            print("  Done!")

        # Download toxic model (needs export - high memory)
        model_name = "martin-ha/toxic-comment-model"
        needs_export = not _check_model_exported(model_name)

        if verbose:
            if needs_export:
                print("Downloading and exporting harmful content model (BERT toxicity)...")
                print("  WARNING: This requires >2GB RAM for ONNX export")
            else:
                print("Loading cached harmful content model...")

        _ORTModelForSequenceClassification.from_pretrained(
            model_name,
            export=needs_export,
            provider="CPUExecutionProvider"
        )
        _AutoTokenizer.from_pretrained(model_name)

        if verbose:
            print("  Done!")
            print("\nModels downloaded successfully!")
            print("All subsequent scans will run 100% locally.")

        return True

    except Exception as e:
        if verbose:
            print(f"ERROR: Failed to download models: {e}")
        return False


class RiskLevel(Enum):
    """Risk severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatInfo:
    """Information about a detected threat"""
    type: str
    confidence: float
    description: str
    level: RiskLevel
    matched_pattern: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "confidence": self.confidence,
            "description": self.description,
            "level": self.level.value,
            "matched_pattern": self.matched_pattern
        }


@dataclass
class ScanResult:
    """Result of a security scan"""
    blocked: bool
    risk_score: float
    threats: List[ThreatInfo] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    scanners_used: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocked": self.blocked,
            "risk_score": self.risk_score,
            "threats": [t.to_dict() for t in self.threats],
            "scan_duration_ms": self.scan_duration_ms,
            "scanners_used": self.scanners_used
        }


class PromptGuard:
    """
    NadiAI Prompt Guard - Local LLM Security Scanner

    Provides fast, offline security scanning for prompts using ONNX models.

    Scanners included:
    - prompt_injection: DeBERTa-based prompt injection detection
    - harmful_content: BERT toxicity/harmful content detection
    - pii_detection: Regex-based PII pattern matching

    Usage:
        guard = PromptGuard()
        result = guard.scan("Your prompt here")

        if result.blocked:
            print(f"Blocked due to: {[t.type for t in result.threats]}")
    """

    # Model configurations
    # Models with has_onnx=True have pre-exported ONNX in subfolder="onnx"
    # Models with has_onnx=False need export=True on first load (memory intensive)
    MODELS = {
        "prompt_injection": {
            "name": "protectai/deberta-v3-base-prompt-injection-v2",
            "threshold": 0.5,
            "description": "Advanced prompt injection detection using DeBERTa",
            "has_onnx": True,  # Pre-exported ONNX available in onnx/ subfolder
            "subfolder": "onnx"
        },
        "harmful_content": {
            "name": "martin-ha/toxic-comment-model",
            "threshold": 0.5,
            "description": "Toxicity and harmful content detection using BERT",
            "has_onnx": False,  # No pre-exported ONNX, needs export
            "subfolder": None
        }
    }

    # PII patterns for regex-based detection
    PII_PATTERNS = {
        "ssn": {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "description": "Social Security Number"
        },
        "credit_card": {
            "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "description": "Credit Card Number"
        },
        "email": {
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "description": "Email Address"
        },
        "phone": {
            "pattern": r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
            "description": "Phone Number"
        },
        "ip_address": {
            "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "description": "IP Address"
        },
        "api_key": {
            "pattern": r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?[\w-]{20,}",
            "description": "API Key or Secret",
            "flags": re.IGNORECASE
        },
        "aws_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "description": "AWS Access Key ID"
        },
        "password": {
            "pattern": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{4,}",
            "description": "Password",
            "flags": re.IGNORECASE
        }
    }

    def __init__(
        self,
        cache_dir: str = "~/.nadiai_prompt_guard/models",
        enable_injection: bool = True,
        enable_harmful: bool = True,
        enable_pii: bool = True,
        injection_threshold: float = 0.5,
        harmful_threshold: float = 0.5,
        block_threshold: float = 0.7,
        auto_load: bool = True,
        verbose: bool = False
    ):
        """
        Initialize PromptGuard scanner.

        Args:
            cache_dir: Directory to cache downloaded models
            enable_injection: Enable prompt injection detection
            enable_harmful: Enable harmful content detection
            enable_pii: Enable PII detection
            injection_threshold: Confidence threshold for injection (0-1)
            harmful_threshold: Confidence threshold for harmful content (0-1)
            block_threshold: Overall risk score threshold for blocking (0-1)
            auto_load: Automatically load models on first scan
            verbose: Enable verbose logging
        """
        self.cache_dir = Path(cache_dir).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.enable_injection = enable_injection
        self.enable_harmful = enable_harmful
        self.enable_pii = enable_pii

        self.injection_threshold = injection_threshold
        self.harmful_threshold = harmful_threshold
        self.block_threshold = block_threshold

        self.verbose = verbose
        self.auto_load = auto_load

        # Model instances (loaded lazily)
        self._models: Dict[str, Any] = {}
        self._tokenizers: Dict[str, Any] = {}
        self._loaded = False

        # Compile PII patterns
        self._pii_patterns = {}
        for name, config in self.PII_PATTERNS.items():
            flags = config.get("flags", 0)
            self._pii_patterns[name] = {
                "regex": re.compile(config["pattern"], flags),
                "description": config["description"]
            }

        if self.verbose:
            logging.basicConfig(level=logging.DEBUG)

    def _log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[PromptGuard] {message}")

    def _model_is_exported(self, model_name: str) -> bool:
        """Check if a model has already been exported to ONNX format in HuggingFace cache."""
        # Check HuggingFace hub cache for ONNX files
        hub_cache = Path.home() / ".cache" / "huggingface" / "hub"
        # Convert model name to cache directory format (e.g., "protectai/model" -> "models--protectai--model")
        cache_name = f"models--{model_name.replace('/', '--')}"
        model_cache = hub_cache / cache_name

        if not model_cache.exists():
            return False

        # Check for ONNX model files in snapshots
        snapshots_dir = model_cache / "snapshots"
        if snapshots_dir.exists():
            for snapshot in snapshots_dir.iterdir():
                if snapshot.is_dir():
                    # Look for .onnx files indicating exported model
                    onnx_files = list(snapshot.glob("*.onnx"))
                    if onnx_files:
                        return True

        return False

    def load_models(self) -> bool:
        """
        Load ONNX models into memory.

        Uses pre-exported ONNX models when available (low memory).
        Falls back to export on first load for models without pre-exported ONNX.

        Returns:
            True if models loaded successfully, False otherwise
        """
        if self._loaded:
            return True

        if not _check_onnx_available():
            logger.error("ONNX Runtime not available. ML-based scanners will be disabled.")
            self._loaded = True  # Mark as loaded to avoid repeated attempts
            return False

        import torch

        try:
            # Load prompt injection model
            if self.enable_injection:
                self._log("Loading prompt injection model...")
                model_config = self.MODELS["prompt_injection"]
                model_name = model_config["name"]
                has_onnx = model_config.get("has_onnx", False)
                subfolder = model_config.get("subfolder")

                if has_onnx and subfolder:
                    # Use pre-exported ONNX (low memory, fast)
                    self._log(f"Using pre-exported ONNX from {subfolder}/ subfolder")
                    self._models["prompt_injection"] = _ORTModelForSequenceClassification.from_pretrained(
                        model_name,
                        export=False,
                        subfolder=subfolder,
                        provider="CPUExecutionProvider"
                    )
                    self._tokenizers["prompt_injection"] = _AutoTokenizer.from_pretrained(
                        model_name,
                        subfolder=subfolder
                    )
                    # Fix tokenizer input names for ONNX compatibility
                    self._tokenizers["prompt_injection"].model_input_names = ["input_ids", "attention_mask"]
                else:
                    # Fall back to export (high memory on first load)
                    needs_export = not self._model_is_exported(model_name)
                    if needs_export:
                        self._log(f"Model {model_name} needs ONNX export (high memory)...")
                    self._models["prompt_injection"] = _ORTModelForSequenceClassification.from_pretrained(
                        model_name,
                        export=needs_export,
                        provider="CPUExecutionProvider",
                        cache_dir=str(self.cache_dir)
                    )
                    self._tokenizers["prompt_injection"] = _AutoTokenizer.from_pretrained(model_name)

                self._log("Prompt injection model loaded")

            # Load harmful content model
            if self.enable_harmful:
                self._log("Loading harmful content model...")
                model_config = self.MODELS["harmful_content"]
                model_name = model_config["name"]
                has_onnx = model_config.get("has_onnx", False)
                subfolder = model_config.get("subfolder")

                if has_onnx and subfolder:
                    # Use pre-exported ONNX (low memory, fast)
                    self._log(f"Using pre-exported ONNX from {subfolder}/ subfolder")
                    self._models["harmful_content"] = _ORTModelForSequenceClassification.from_pretrained(
                        model_name,
                        export=False,
                        subfolder=subfolder,
                        provider="CPUExecutionProvider"
                    )
                    self._tokenizers["harmful_content"] = _AutoTokenizer.from_pretrained(
                        model_name,
                        subfolder=subfolder
                    )
                else:
                    # Fall back to export (high memory on first load)
                    needs_export = not self._model_is_exported(model_name)
                    if needs_export:
                        self._log(f"Model {model_name} needs ONNX export (high memory)...")
                    self._models["harmful_content"] = _ORTModelForSequenceClassification.from_pretrained(
                        model_name,
                        export=needs_export,
                        provider="CPUExecutionProvider",
                        cache_dir=str(self.cache_dir)
                    )
                    self._tokenizers["harmful_content"] = _AutoTokenizer.from_pretrained(model_name)

                self._log("Harmful content model loaded")

            self._loaded = True
            self._log("All models loaded successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            self._loaded = True  # Mark as loaded to avoid repeated attempts
            return False

    def _scan_injection(self, text: str) -> Optional[ThreatInfo]:
        """Scan for prompt injection attacks"""
        if "prompt_injection" not in self._models:
            return None

        import torch

        try:
            model = self._models["prompt_injection"]
            tokenizer = self._tokenizers["prompt_injection"]

            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)

            with torch.no_grad():
                outputs = model(**inputs)
                predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)

            # Model outputs: [benign, injection]
            injection_score = predictions[0][1].item()

            if injection_score > self.injection_threshold:
                level = RiskLevel.CRITICAL if injection_score > 0.9 else (
                    RiskLevel.HIGH if injection_score > 0.7 else RiskLevel.MEDIUM
                )
                return ThreatInfo(
                    type="prompt_injection",
                    confidence=injection_score,
                    description=f"Prompt injection detected with {injection_score:.1%} confidence",
                    level=level
                )

            return None

        except Exception as e:
            logger.error(f"Error in injection scan: {e}")
            return None

    def _scan_harmful(self, text: str) -> Optional[ThreatInfo]:
        """Scan for harmful/toxic content"""
        if "harmful_content" not in self._models:
            return None

        import torch

        try:
            model = self._models["harmful_content"]
            tokenizer = self._tokenizers["harmful_content"]

            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)

            with torch.no_grad():
                outputs = model(**inputs)
                predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)

            # Model outputs: [non-toxic, toxic]
            toxic_score = predictions[0][1].item() if predictions.shape[1] >= 2 else predictions[0][0].item()

            if toxic_score > self.harmful_threshold:
                level = RiskLevel.CRITICAL if toxic_score > 0.9 else (
                    RiskLevel.HIGH if toxic_score > 0.7 else RiskLevel.MEDIUM
                )
                return ThreatInfo(
                    type="harmful_content",
                    confidence=toxic_score,
                    description=f"Harmful/toxic content detected with {toxic_score:.1%} confidence",
                    level=level
                )

            return None

        except Exception as e:
            logger.error(f"Error in harmful content scan: {e}")
            return None

    def _scan_pii(self, text: str) -> List[ThreatInfo]:
        """Scan for PII using regex patterns"""
        threats = []

        for pii_type, config in self._pii_patterns.items():
            matches = config["regex"].findall(text)
            if matches:
                # Mask the matched value for security
                masked = matches[0][:4] + "***" if len(matches[0]) > 4 else "***"
                threats.append(ThreatInfo(
                    type=f"pii_{pii_type}",
                    confidence=1.0,  # Regex matches are definitive
                    description=f"{config['description']} detected",
                    level=RiskLevel.HIGH if pii_type in ["ssn", "credit_card", "password", "aws_key"] else RiskLevel.MEDIUM,
                    matched_pattern=masked
                ))

        return threats

    def scan(self, text: str) -> ScanResult:
        """
        Scan text for security threats.

        Args:
            text: The text/prompt to scan

        Returns:
            ScanResult with threat information and risk score
        """
        start_time = time.time()
        threats: List[ThreatInfo] = []
        scanners_used: List[str] = []

        # Auto-load models if needed
        if self.auto_load and not self._loaded:
            self.load_models()

        # Run prompt injection scan
        if self.enable_injection and "prompt_injection" in self._models:
            scanners_used.append("prompt_injection")
            threat = self._scan_injection(text)
            if threat:
                threats.append(threat)

        # Run harmful content scan
        if self.enable_harmful and "harmful_content" in self._models:
            scanners_used.append("harmful_content")
            threat = self._scan_harmful(text)
            if threat:
                threats.append(threat)

        # Run PII scan
        if self.enable_pii:
            scanners_used.append("pii_detection")
            pii_threats = self._scan_pii(text)
            threats.extend(pii_threats)

        # Calculate overall risk score
        if threats:
            risk_score = max(t.confidence for t in threats)
        else:
            risk_score = 0.0

        # Determine if prompt should be blocked
        blocked = risk_score >= self.block_threshold or any(
            t.level in [RiskLevel.HIGH, RiskLevel.CRITICAL] for t in threats
        )

        scan_duration = (time.time() - start_time) * 1000  # Convert to ms

        result = ScanResult(
            blocked=blocked,
            risk_score=risk_score,
            threats=threats,
            scan_duration_ms=round(scan_duration, 2),
            scanners_used=scanners_used
        )

        if self.verbose:
            status = "BLOCKED" if blocked else "SAFE"
            self._log(f"[{status}] Risk: {risk_score:.2f}, Threats: {len(threats)}, Duration: {scan_duration:.1f}ms")

        return result

    def scan_batch(self, texts: List[str]) -> List[ScanResult]:
        """
        Scan multiple texts for security threats.

        Args:
            texts: List of texts/prompts to scan

        Returns:
            List of ScanResult objects
        """
        return [self.scan(text) for text in texts]

    def get_status(self) -> Dict[str, Any]:
        """Get scanner status and configuration"""
        return {
            "loaded": self._loaded,
            "models_available": list(self._models.keys()),
            "scanners_enabled": {
                "prompt_injection": self.enable_injection,
                "harmful_content": self.enable_harmful,
                "pii_detection": self.enable_pii
            },
            "thresholds": {
                "injection": self.injection_threshold,
                "harmful": self.harmful_threshold,
                "block": self.block_threshold
            },
            "cache_dir": str(self.cache_dir),
            "onnx_available": _check_onnx_available()
        }
