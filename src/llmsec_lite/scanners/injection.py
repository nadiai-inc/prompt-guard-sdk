"""Prompt injection scanner for LLMSEC LITE."""

from __future__ import annotations

import numpy as np
import structlog

from llmsec_lite.scanners.base import ONNXScanner, ScannerResult
from llmsec_lite.schemas.results import Finding, Severity
from llmsec_lite.models.onnx_runtime import softmax

logger = structlog.get_logger(__name__)


class InjectionScanner(ONNXScanner):
    """Scanner for detecting prompt injection attacks.

    Uses a DeBERTa-v3-base model fine-tuned on prompt injection detection.
    The model classifies text as either:
    - SAFE (0): Normal user input
    - INJECTION (1): Potential prompt injection attack

    Detects:
    - Jailbreak attempts
    - "Ignore previous instructions" attacks
    - Role hijacking
    - System prompt extraction
    - Instruction override attempts
    """

    scanner_id = "injection"
    direction = "input"  # Only for input scanning
    model_filename = "injection_int8.onnx"

    # Known injection patterns for additional heuristic checks
    INJECTION_PATTERNS = [
        "ignore previous instructions",
        "ignore all previous",
        "disregard previous",
        "forget previous",
        "ignore your instructions",
        "ignore the above",
        "do not follow",
        "override your",
        "you are now",
        "act as if you",
        "pretend you are",
        "from now on you",
        "you will now",
        "new instructions:",
        "system prompt:",
        "reveal your prompt",
        "show your instructions",
        "what are your instructions",
        "repeat your prompt",
        "dan mode",
        "jailbreak",
        "developer mode",
        "sudo mode",
        "maintenance mode",
    ]

    def __init__(self, cache_dir: str = "~/.llmsec-lite") -> None:
        """Initialize injection scanner.

        Args:
            cache_dir: Directory for model cache
        """
        super().__init__(cache_dir)
        self._inference = None

    async def initialize(self) -> None:
        """Load ONNX model and tokenizer."""
        from llmsec_lite.models.onnx_runtime import load_model

        try:
            self._inference, self._tokenizer = await load_model(
                "injection",
                self.cache_dir,
            )
            await super().initialize()
        except Exception as e:
            logger.warning(
                "Failed to load injection model, will use heuristics only",
                error=str(e),
            )
            self._initialized = True

    def _check_patterns(self, text: str) -> tuple[float, list[str]]:
        """Check for known injection patterns.

        Args:
            text: Text to check

        Returns:
            Tuple of (score, matched_patterns)
        """
        text_lower = text.lower()
        matched = []

        for pattern in self.INJECTION_PATTERNS:
            if pattern in text_lower:
                matched.append(pattern)

        if not matched:
            return 0.0, []

        # Score based on number of patterns matched
        score = min(0.95, 0.4 + (len(matched) * 0.15))
        return score, matched

    async def scan(
        self,
        text: str,
        context: str | None = None,
    ) -> ScannerResult:
        """Scan text for prompt injection.

        Args:
            text: Text to scan
            context: Unused for injection scanner

        Returns:
            ScannerResult with findings
        """
        await self.ensure_initialized()

        findings: list[Finding] = []
        model_score = 0.0
        pattern_score, matched_patterns = self._check_patterns(text)

        # Try model inference if available
        if self._inference is not None:
            try:
                outputs = self._inference.predict(text)

                # Get logits from model output
                # Assuming binary classification: [safe, injection]
                logits = None
                for key in ["logits", "output", "outputs"]:
                    if key in outputs:
                        logits = outputs[key]
                        break

                if logits is None:
                    logits = list(outputs.values())[0]

                # Apply softmax to get probabilities
                probs = softmax(logits)

                # Get injection probability (index 1)
                if len(probs.shape) > 1:
                    model_score = float(probs[0, 1])
                else:
                    model_score = float(probs[1])

            except Exception as e:
                logger.warning("Model inference failed", error=str(e))
                model_score = 0.0

        # Combine scores (prefer model if available)
        if self._inference is not None and model_score > 0:
            final_score = max(model_score, pattern_score * 0.8)
        else:
            final_score = pattern_score

        # Determine severity based on score
        if final_score >= 0.9:
            severity = Severity.CRITICAL
        elif final_score >= 0.7:
            severity = Severity.HIGH
        elif final_score >= 0.5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Create findings if score is significant
        if final_score > 0.3:
            details = {
                "model_score": model_score,
                "pattern_score": pattern_score,
                "matched_patterns": matched_patterns,
            }

            # Determine the type of injection
            injection_type = "prompt_injection"
            if any(p in ["dan mode", "jailbreak", "developer mode"] for p in matched_patterns):
                injection_type = "jailbreak_attempt"
            elif any(p in ["reveal your prompt", "show your instructions", "repeat your prompt"] for p in matched_patterns):
                injection_type = "prompt_extraction"
            elif any(p in ["ignore previous", "ignore all previous", "disregard previous"] for p in matched_patterns):
                injection_type = "instruction_override"

            # Truncate text for display
            display_text = text[:100] + "..." if len(text) > 100 else text

            findings.append(
                Finding(
                    type=injection_type,
                    value=display_text,
                    location=(0, len(text)),
                    severity=severity,
                    confidence=final_score,
                    details=details,
                )
            )

        return ScannerResult(
            score=final_score,
            findings=findings,
            metadata={
                "model_available": self._inference is not None,
                "model_score": model_score,
                "pattern_score": pattern_score,
            },
        )
