"""Hallucination detection scanner for LLMSEC LITE."""

from __future__ import annotations

import json
from typing import Any

import structlog

from llmsec_lite.scanners.base import LLMScanner, ScannerResult
from llmsec_lite.schemas.results import Finding, Severity

logger = structlog.get_logger(__name__)


# System prompt for hallucination detection
HALLUCINATION_JUDGE_SYSTEM = """You are a hallucination detector. Your job is to compare an LLM's response against source context and identify any hallucinations.

A hallucination is when the LLM:
1. States facts that contradict the source
2. Makes claims not supported by the source
3. Invents citations, names, statistics, or references
4. Makes confident statements about things that are uncertain or unknown
5. Adds details that were not in the source

You must be thorough and careful. Return your analysis as JSON."""


HALLUCINATION_JUDGE_PROMPT = """Compare the SOURCE (ground truth) with the RESPONSE (LLM output) and identify any hallucinations.

SOURCE (ground truth):
\"\"\"
{context}
\"\"\"

RESPONSE (LLM output):
\"\"\"
{text}
\"\"\"

Analyze the response for:
1. Facts that contradict the source
2. Facts not supported by the source
3. Made-up citations, names, or statistics
4. Confident statements about uncertain things

Return JSON with this structure:
{{
  "faithful": true/false,
  "confidence": 0.0-1.0,
  "hallucinations": [
    {{
      "claim": "the specific claim made",
      "issue": "why this is a hallucination",
      "severity": "low/medium/high/critical"
    }}
  ],
  "summary": "brief summary of the analysis"
}}"""


class HallucinationScanner(LLMScanner):
    """Scanner for detecting hallucinations in LLM outputs.

    Uses an LLM as a judge to compare the response against the source context
    and identify any hallucinated content.

    Requires:
    - API key for OpenAI (or compatible API)
    - Source context to compare against
    """

    scanner_id = "hallucination"
    direction = "output"  # Only for output scanning
    requires_api_key = True

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
    ) -> None:
        """Initialize hallucination scanner.

        Args:
            api_key: OpenAI API key
            model: Model to use for judging
        """
        super().__init__(api_key)
        self.model = model

    async def initialize(self) -> None:
        """Initialize LLM client."""
        from llmsec_lite.models.llm_client import create_client

        self._client = create_client(
            api_key=self.api_key,
            model=self.model,
        )
        await super().initialize()

    def _parse_response(self, response: dict[str, Any]) -> tuple[float, list[Finding]]:
        """Parse the LLM judge response.

        Args:
            response: Parsed JSON response from LLM

        Returns:
            Tuple of (score, findings)
        """
        findings: list[Finding] = []

        # Get faithfulness assessment
        is_faithful = response.get("faithful", True)
        confidence = response.get("confidence", 0.5)
        hallucinations = response.get("hallucinations", [])

        # Calculate score (inverse of faithfulness)
        if is_faithful:
            score = 1.0 - confidence  # Low score if faithful
        else:
            score = confidence  # High score if unfaithful

        # Create findings for each hallucination
        for hal in hallucinations:
            claim = hal.get("claim", "Unknown claim")
            issue = hal.get("issue", "Unknown issue")
            severity_str = hal.get("severity", "medium")

            # Map severity
            severity_map = {
                "low": Severity.LOW,
                "medium": Severity.MEDIUM,
                "high": Severity.HIGH,
                "critical": Severity.CRITICAL,
            }
            severity = severity_map.get(severity_str.lower(), Severity.MEDIUM)

            findings.append(
                Finding(
                    type="hallucination",
                    value=claim[:200] + "..." if len(claim) > 200 else claim,
                    location=(0, 0),  # Position not available for semantic analysis
                    severity=severity,
                    confidence=confidence,
                    details={
                        "issue": issue,
                        "full_claim": claim,
                    },
                )
            )

        return score, findings

    async def scan(
        self,
        text: str,
        context: str | None = None,
    ) -> ScannerResult:
        """Scan text for hallucinations.

        Args:
            text: LLM response to scan
            context: Source context to compare against (required)

        Returns:
            ScannerResult with findings
        """
        await self.ensure_initialized()

        # Context is required for hallucination detection
        if not context:
            logger.warning("No context provided for hallucination detection")
            return ScannerResult(
                score=0.0,
                findings=[],
                metadata={"error": "No context provided"},
            )

        if not self._client:
            logger.warning("LLM client not available")
            return ScannerResult(
                score=0.0,
                findings=[],
                metadata={"error": "LLM client not available"},
            )

        try:
            # Build the prompt
            prompt = HALLUCINATION_JUDGE_PROMPT.format(
                context=context[:4000],  # Limit context length
                text=text[:4000],  # Limit response length
            )

            # Call the LLM
            response = await self._client.complete_json(
                prompt=prompt,
                system_prompt=HALLUCINATION_JUDGE_SYSTEM,
                temperature=0.0,
                max_tokens=1024,
            )

            # Parse the response
            score, findings = self._parse_response(response)

            return ScannerResult(
                score=score,
                findings=findings,
                metadata={
                    "faithful": response.get("faithful"),
                    "summary": response.get("summary"),
                    "raw_response": response,
                },
            )

        except Exception as e:
            logger.error("Hallucination scan failed", error=str(e))
            return ScannerResult(
                score=0.0,
                findings=[],
                metadata={"error": str(e)},
            )


class SimpleHallucinationScanner(LLMScanner):
    """Simplified hallucination scanner using basic heuristics.

    This scanner doesn't require an API key and uses simple heuristics
    to detect potential hallucinations. Less accurate but faster.
    """

    scanner_id = "hallucination_simple"
    direction = "output"
    requires_api_key = False

    # Phrases that often indicate fabrication
    FABRICATION_INDICATORS = [
        "studies show",
        "research indicates",
        "according to experts",
        "statistics show",
        "data suggests",
        "scientists have found",
        "a recent study",
        "it has been proven",
        "evidence suggests",
        "it is well known that",
        "historically speaking",
        "as we all know",
    ]

    # Citation patterns that might be fabricated
    CITATION_PATTERNS = [
        r"\(\d{4}\)",  # Year in parentheses like (2023)
        r"et al\.",  # Academic citation
        r"vol\. \d+",  # Volume number
        r"pp\. \d+",  # Page numbers
    ]

    async def scan(
        self,
        text: str,
        context: str | None = None,
    ) -> ScannerResult:
        """Scan text for potential hallucinations using heuristics.

        Args:
            text: LLM response to scan
            context: Source context (used for comparison if provided)

        Returns:
            ScannerResult with findings
        """
        import re

        findings: list[Finding] = []
        score = 0.0
        matched_indicators: list[str] = []

        text_lower = text.lower()

        # Check for fabrication indicators
        for indicator in self.FABRICATION_INDICATORS:
            if indicator in text_lower:
                matched_indicators.append(indicator)

        # Check for citation patterns
        citations_found = []
        for pattern in self.CITATION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            citations_found.extend(matches)

        # Calculate score
        indicator_score = min(0.5, len(matched_indicators) * 0.1)
        citation_score = min(0.3, len(citations_found) * 0.1)
        score = indicator_score + citation_score

        # Context comparison (if provided)
        context_mismatch = False
        if context:
            # Very basic check: look for claims not in context
            # This is a simplified heuristic
            context_lower = context.lower()
            for indicator in matched_indicators:
                idx = text_lower.find(indicator)
                if idx != -1:
                    # Get surrounding text
                    start = max(0, idx - 50)
                    end = min(len(text), idx + len(indicator) + 100)
                    claim = text[start:end]

                    # Check if key words from claim are in context
                    words = set(claim.lower().split())
                    context_words = set(context_lower.split())
                    overlap = len(words & context_words) / len(words) if words else 0

                    if overlap < 0.3:
                        context_mismatch = True
                        score += 0.2

        # Create findings
        if matched_indicators or (citations_found and not context):
            severity = Severity.MEDIUM if score < 0.5 else Severity.HIGH

            findings.append(
                Finding(
                    type="potential_hallucination",
                    value=f"Found {len(matched_indicators)} fabrication indicators",
                    location=(0, len(text)),
                    severity=severity,
                    confidence=min(0.7, score),  # Cap confidence for heuristics
                    details={
                        "indicators": matched_indicators,
                        "citations": citations_found,
                        "context_mismatch": context_mismatch,
                    },
                )
            )

        return ScannerResult(
            score=min(0.9, score),  # Cap score for heuristic-based detection
            findings=findings,
            metadata={
                "indicators_found": matched_indicators,
                "citations_found": citations_found,
                "context_mismatch": context_mismatch,
            },
        )
