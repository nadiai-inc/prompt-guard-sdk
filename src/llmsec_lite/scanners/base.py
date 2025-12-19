"""Base scanner abstract class for LLMSEC LITE."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from llmsec_lite.schemas.results import Finding


@dataclass
class ScannerResult:
    """Raw result from a scanner before threshold processing."""

    score: float  # Risk score 0.0 - 1.0
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseScanner(ABC):
    """Abstract base class for all scanners.

    All scanners must implement the async scan method.
    Scanners should be designed to:
    - Never crash on invalid input
    - Fail open (return safe result on error)
    - Support lazy loading of models
    """

    # Scanner ID (e.g., 'injection', 'pii')
    scanner_id: str = ""

    # Direction: 'input', 'output', or 'both'
    direction: Literal["input", "output", "both"] = "both"

    # Whether this scanner requires API key
    requires_api_key: bool = False

    # Whether this scanner uses ONNX models
    uses_onnx: bool = False

    def __init__(self) -> None:
        """Initialize the scanner."""
        self._initialized = False

    @abstractmethod
    async def scan(
        self,
        text: str,
        context: str | None = None,
    ) -> ScannerResult:
        """Scan text for threats.

        Args:
            text: Text to scan
            context: Optional context (e.g., original prompt for hallucination check)

        Returns:
            ScannerResult with score and findings
        """
        ...

    async def initialize(self) -> None:
        """Initialize the scanner (lazy loading).

        Override this to load models, compile patterns, etc.
        Called automatically on first scan if not already initialized.
        """
        self._initialized = True

    async def ensure_initialized(self) -> None:
        """Ensure scanner is initialized before use."""
        if not self._initialized:
            await self.initialize()

    def get_info(self) -> dict[str, Any]:
        """Get scanner information."""
        return {
            "scanner_id": self.scanner_id,
            "direction": self.direction,
            "requires_api_key": self.requires_api_key,
            "uses_onnx": self.uses_onnx,
            "initialized": self._initialized,
        }


class RegexScanner(BaseScanner):
    """Base class for regex-based scanners."""

    uses_onnx = False
    requires_api_key = False

    def __init__(self) -> None:
        """Initialize regex scanner."""
        super().__init__()
        self._patterns: list[dict[str, Any]] = []

    async def initialize(self) -> None:
        """Load and compile patterns."""
        self._patterns = await self._load_patterns()
        await super().initialize()

    @abstractmethod
    async def _load_patterns(self) -> list[dict[str, Any]]:
        """Load patterns for this scanner.

        Returns:
            List of pattern dictionaries with 'id', 'pattern', 'severity', etc.
        """
        ...


class ONNXScanner(BaseScanner):
    """Base class for ONNX model-based scanners."""

    uses_onnx = True
    requires_api_key = False

    # Model filename (e.g., 'injection_int8.onnx')
    model_filename: str = ""

    def __init__(self, cache_dir: str = "~/.llmsec-lite") -> None:
        """Initialize ONNX scanner.

        Args:
            cache_dir: Directory for model cache
        """
        super().__init__()
        self.cache_dir = cache_dir
        self._session = None
        self._tokenizer = None

    async def initialize(self) -> None:
        """Load ONNX model and tokenizer."""
        from llmsec_lite.models.onnx_runtime import load_model

        self._session, self._tokenizer = await load_model(
            self.model_filename,
            self.cache_dir,
        )
        await super().initialize()


class LLMScanner(BaseScanner):
    """Base class for LLM-based scanners."""

    uses_onnx = False
    requires_api_key = True

    def __init__(self, api_key: str | None = None) -> None:
        """Initialize LLM scanner.

        Args:
            api_key: OpenAI API key
        """
        super().__init__()
        self.api_key = api_key
        self._client = None

    async def initialize(self) -> None:
        """Initialize LLM client."""
        from llmsec_lite.models.llm_client import create_client

        self._client = create_client(self.api_key)
        await super().initialize()
