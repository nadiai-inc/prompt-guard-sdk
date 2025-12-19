"""Toxicity scanner for LLMSEC LITE."""

from __future__ import annotations

import numpy as np
import structlog

from llmsec_lite.scanners.base import ONNXScanner, ScannerResult
from llmsec_lite.schemas.results import Finding, Severity
from llmsec_lite.models.onnx_runtime import sigmoid

logger = structlog.get_logger(__name__)


class ToxicityScanner(ONNXScanner):
    """Scanner for detecting toxic content.

    Uses a Toxic-BERT model for multi-label toxicity classification.
    Detects multiple toxicity categories:
    - Toxic
    - Severe toxicity
    - Obscene
    - Threat
    - Insult
    - Identity attack
    """

    scanner_id = "toxicity"
    direction = "both"  # Can scan both input and output
    model_filename = "toxicity_int8.onnx"

    # Toxicity categories from the model
    TOXICITY_LABELS = [
        "toxic",
        "severe_toxic",
        "obscene",
        "threat",
        "insult",
        "identity_attack",
    ]

    # Known toxic patterns for fallback heuristics
    TOXIC_PATTERNS = [
        # Profanity and obscenity (partial patterns)
        "idiot",
        "stupid",
        "moron",
        "dumb",
        "hate you",
        "kill you",
        "die",
        "threat",
        # Hate speech indicators
        "all [group] are",
        "those people",
        # Violence
        "hurt you",
        "destroy",
        "attack",
    ]

    def __init__(self, cache_dir: str = "~/.llmsec-lite") -> None:
        """Initialize toxicity scanner.

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
                "toxicity",
                self.cache_dir,
            )
            await super().initialize()
        except Exception as e:
            logger.warning(
                "Failed to load toxicity model, will use heuristics only",
                error=str(e),
            )
            self._initialized = True

    def _check_patterns(self, text: str) -> tuple[float, list[str]]:
        """Check for known toxic patterns.

        Args:
            text: Text to check

        Returns:
            Tuple of (score, matched_patterns)
        """
        text_lower = text.lower()
        matched = []

        for pattern in self.TOXIC_PATTERNS:
            if pattern in text_lower:
                matched.append(pattern)

        if not matched:
            return 0.0, []

        # Score based on number of patterns matched
        score = min(0.9, 0.3 + (len(matched) * 0.15))
        return score, matched

    async def scan(
        self,
        text: str,
        context: str | None = None,
    ) -> ScannerResult:
        """Scan text for toxicity.

        Args:
            text: Text to scan
            context: Unused for toxicity scanner

        Returns:
            ScannerResult with findings
        """
        await self.ensure_initialized()

        findings: list[Finding] = []
        label_scores: dict[str, float] = {}
        model_score = 0.0
        pattern_score, matched_patterns = self._check_patterns(text)

        # Try model inference if available
        if self._inference is not None:
            try:
                outputs = self._inference.predict(text)

                # Get logits from model output
                logits = None
                for key in ["logits", "output", "outputs"]:
                    if key in outputs:
                        logits = outputs[key]
                        break

                if logits is None:
                    logits = list(outputs.values())[0]

                # Apply sigmoid for multi-label classification
                probs = sigmoid(logits)

                if len(probs.shape) > 1:
                    probs = probs[0]

                # Map to labels
                for i, label in enumerate(self.TOXICITY_LABELS):
                    if i < len(probs):
                        label_scores[label] = float(probs[i])

                # Overall toxicity score (max of all labels)
                model_score = max(label_scores.values()) if label_scores else 0.0

            except Exception as e:
                logger.warning("Model inference failed", error=str(e))
                model_score = 0.0

        # Combine scores
        if self._inference is not None and model_score > 0:
            final_score = max(model_score, pattern_score * 0.7)
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

        # Create findings for detected toxicity
        if final_score > 0.3:
            # Find the primary toxicity type
            primary_type = "toxic"
            if label_scores:
                primary_type = max(label_scores, key=lambda k: label_scores[k])

            # Collect high-scoring labels
            high_labels = [
                label for label, score in label_scores.items()
                if score > 0.5
            ]

            details = {
                "label_scores": label_scores,
                "matched_patterns": matched_patterns,
                "toxicity_types": high_labels or [primary_type],
            }

            # Truncate text for display
            display_text = text[:100] + "..." if len(text) > 100 else text

            findings.append(
                Finding(
                    type=primary_type,
                    value=display_text,
                    location=(0, len(text)),
                    severity=severity,
                    confidence=final_score,
                    details=details,
                )
            )

            # Add findings for specific high-severity labels
            for label, score in label_scores.items():
                if label != primary_type and score > 0.7:
                    label_severity = Severity.CRITICAL if score > 0.9 else Severity.HIGH
                    findings.append(
                        Finding(
                            type=label,
                            value=f"Detected {label.replace('_', ' ')}",
                            location=(0, len(text)),
                            severity=label_severity,
                            confidence=score,
                            details={"score": score},
                        )
                    )

        return ScannerResult(
            score=final_score,
            findings=findings,
            metadata={
                "model_available": self._inference is not None,
                "label_scores": label_scores,
                "pattern_score": pattern_score,
            },
        )
