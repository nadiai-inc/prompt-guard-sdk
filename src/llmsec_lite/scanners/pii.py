"""PII (Personally Identifiable Information) scanner for LLMSEC LITE."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from llmsec_lite.scanners.base import RegexScanner, ScannerResult
from llmsec_lite.schemas.results import Finding, Severity
from llmsec_lite.schemas.config import RedactionStyle


class PIIScanner(RegexScanner):
    """Scanner for detecting and optionally redacting PII."""

    scanner_id = "pii"
    direction = "both"

    def __init__(
        self,
        redaction_enabled: bool = True,
        redaction_style: RedactionStyle = RedactionStyle.FULL,
    ) -> None:
        """Initialize PII scanner.

        Args:
            redaction_enabled: Whether to enable PII redaction
            redaction_style: Style of redaction to apply
        """
        super().__init__()
        self.redaction_enabled = redaction_enabled
        self.redaction_style = redaction_style
        self._compiled_patterns: list[tuple[re.Pattern[str], dict[str, Any]]] = []

    async def _load_patterns(self) -> list[dict[str, Any]]:
        """Load PII patterns from JSON file."""
        patterns_path = Path(__file__).parent.parent / "patterns" / "pii.json"

        if patterns_path.exists():
            with open(patterns_path) as f:
                data = json.load(f)
                return data.get("patterns", [])

        return self._get_default_patterns()

    def _get_default_patterns(self) -> list[dict[str, Any]]:
        """Get default PII patterns."""
        return [
            {
                "id": "ssn",
                "name": "Social Security Number",
                "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
                "severity": "critical",
                "redaction_partial": "***-**-{last4}",
            },
            {
                "id": "credit_card_visa",
                "name": "Visa Credit Card",
                "pattern": r"\b4[0-9]{12}(?:[0-9]{3})?\b",
                "severity": "critical",
                "redaction_partial": "****-****-****-{last4}",
            },
            {
                "id": "credit_card_mastercard",
                "name": "Mastercard",
                "pattern": r"\b5[1-5][0-9]{14}\b",
                "severity": "critical",
                "redaction_partial": "****-****-****-{last4}",
            },
            {
                "id": "credit_card_amex",
                "name": "American Express",
                "pattern": r"\b3[47][0-9]{13}\b",
                "severity": "critical",
                "redaction_partial": "****-******-*{last4}",
            },
            {
                "id": "credit_card_discover",
                "name": "Discover Card",
                "pattern": r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",
                "severity": "critical",
                "redaction_partial": "****-****-****-{last4}",
            },
            {
                "id": "phone_us",
                "name": "US Phone Number",
                "pattern": r"\b(?:\+1[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
                "severity": "medium",
                "redaction_partial": "(***) ***-{last4}",
            },
            {
                "id": "email",
                "name": "Email Address",
                "pattern": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
                "severity": "medium",
                "redaction_partial": "{first}***@***.***",
            },
            {
                "id": "ip_address",
                "name": "IP Address",
                "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                "severity": "low",
                "redaction_partial": "***.***.***.***",
            },
            {
                "id": "date_of_birth",
                "name": "Date of Birth",
                "pattern": r"(?i)\b(?:dob|birth\s*date|date\s*of\s*birth)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
                "severity": "high",
                "redaction_partial": "[DOB REDACTED]",
            },
            {
                "id": "drivers_license",
                "name": "Driver's License",
                "pattern": r"(?i)\b(?:driver'?s?\s*license|dl)[:\s#]*[A-Z0-9]{5,15}\b",
                "severity": "high",
                "redaction_partial": "[DL REDACTED]",
            },
            {
                "id": "passport",
                "name": "Passport Number",
                "pattern": r"(?i)\b(?:passport)[:\s#]*[A-Z0-9]{6,12}\b",
                "severity": "high",
                "redaction_partial": "[PASSPORT REDACTED]",
            },
            {
                "id": "bank_account",
                "name": "Bank Account Number",
                "pattern": r"(?i)\b(?:account|acct)[:\s#]*\d{8,17}\b",
                "severity": "critical",
                "redaction_partial": "[ACCOUNT REDACTED]",
            },
            {
                "id": "routing_number",
                "name": "Bank Routing Number",
                "pattern": r"(?i)\b(?:routing|aba)[:\s#]*\d{9}\b",
                "severity": "high",
                "redaction_partial": "[ROUTING REDACTED]",
            },
        ]

    async def initialize(self) -> None:
        """Compile regex patterns for efficiency."""
        self._patterns = await self._load_patterns()
        self._compiled_patterns = []

        for pattern_def in self._patterns:
            try:
                compiled = re.compile(pattern_def["pattern"])
                self._compiled_patterns.append((compiled, pattern_def))
            except re.error:
                continue

        await super().initialize()

    def _redact_value(self, value: str, pattern_def: dict[str, Any]) -> str:
        """Redact a PII value based on configuration.

        Args:
            value: The matched PII value
            pattern_def: Pattern definition with redaction info

        Returns:
            Redacted string
        """
        if self.redaction_style == RedactionStyle.FULL:
            return "[REDACTED]"

        if self.redaction_style == RedactionStyle.HASH:
            import hashlib

            hash_val = hashlib.sha256(value.encode()).hexdigest()[:8]
            return f"[PII:{hash_val}]"

        # Partial redaction
        partial_template = pattern_def.get("redaction_partial", "[REDACTED]")

        # Handle common partial redaction patterns
        if "{last4}" in partial_template and len(value) >= 4:
            return partial_template.replace("{last4}", value[-4:])
        if "{first}" in partial_template and len(value) >= 1:
            return partial_template.replace("{first}", value[0])

        return partial_template

    async def scan(
        self,
        text: str,
        context: str | None = None,
    ) -> ScannerResult:
        """Scan text for PII.

        Args:
            text: Text to scan
            context: Unused for PII scanner

        Returns:
            ScannerResult with findings
        """
        await self.ensure_initialized()

        findings: list[Finding] = []
        max_score = 0.0
        redacted_text = text

        # Track redaction offsets for accurate replacement
        offset = 0

        for pattern, pattern_def in self._compiled_patterns:
            for match in pattern.finditer(text):
                severity_str = pattern_def.get("severity", "medium")
                severity = Severity(severity_str)

                severity_scores = {
                    Severity.LOW: 0.3,
                    Severity.MEDIUM: 0.5,
                    Severity.HIGH: 0.7,
                    Severity.CRITICAL: 0.95,
                }
                score = severity_scores.get(severity, 0.5)
                max_score = max(max_score, score)

                matched_value = match.group()

                # Create redacted version for display
                redacted_value = self._redact_value(matched_value, pattern_def)

                findings.append(
                    Finding(
                        type=pattern_def.get("id", "pii"),
                        value=redacted_value,
                        location=(match.start(), match.end()),
                        severity=severity,
                        confidence=0.9,
                        details={
                            "pattern_name": pattern_def.get("name", "Unknown"),
                            "pii_type": pattern_def.get("id", "unknown"),
                        },
                    )
                )

        # Apply redactions if enabled
        if self.redaction_enabled and findings:
            # Sort findings by position (reverse) to maintain offsets
            sorted_findings = sorted(findings, key=lambda f: f.location[0], reverse=True)
            for finding in sorted_findings:
                start, end = finding.location
                redacted_text = redacted_text[:start] + finding.value + redacted_text[end:]

        return ScannerResult(
            score=max_score,
            findings=findings,
            metadata={"redacted_text": redacted_text if self.redaction_enabled else None},
        )

    def get_redacted_text(self, result: ScannerResult) -> str | None:
        """Get redacted text from scan result.

        Args:
            result: ScannerResult from scan()

        Returns:
            Redacted text or None
        """
        return result.metadata.get("redacted_text")
