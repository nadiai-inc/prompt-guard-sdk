"""Secrets detection scanner for LLMSEC LITE."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from llmsec_lite.scanners.base import RegexScanner, ScannerResult
from llmsec_lite.schemas.results import Finding, Severity


class SecretsScanner(RegexScanner):
    """Scanner for detecting secrets, API keys, and credentials."""

    scanner_id = "secrets"
    direction = "both"

    def __init__(self) -> None:
        """Initialize secrets scanner."""
        super().__init__()
        self._compiled_patterns: list[tuple[re.Pattern[str], dict[str, Any]]] = []

    async def _load_patterns(self) -> list[dict[str, Any]]:
        """Load secrets patterns from JSON file."""
        patterns_path = Path(__file__).parent.parent / "patterns" / "secrets.json"

        if patterns_path.exists():
            with open(patterns_path) as f:
                data = json.load(f)
                return data.get("patterns", [])

        # Fallback to embedded patterns if file not found
        return self._get_default_patterns()

    def _get_default_patterns(self) -> list[dict[str, Any]]:
        """Get default secrets patterns."""
        return [
            {
                "id": "aws_access_key",
                "name": "AWS Access Key",
                "pattern": r"AKIA[0-9A-Z]{16}",
                "severity": "critical",
            },
            {
                "id": "aws_secret_key",
                "name": "AWS Secret Key",
                "pattern": r"(?i)(aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
                "severity": "critical",
            },
            {
                "id": "github_token",
                "name": "GitHub Token",
                "pattern": r"ghp_[a-zA-Z0-9]{36}",
                "severity": "critical",
            },
            {
                "id": "github_oauth",
                "name": "GitHub OAuth",
                "pattern": r"gho_[a-zA-Z0-9]{36}",
                "severity": "critical",
            },
            {
                "id": "openai_key",
                "name": "OpenAI API Key",
                "pattern": r"sk-[a-zA-Z0-9]{48,}",
                "severity": "critical",
            },
            {
                "id": "anthropic_key",
                "name": "Anthropic API Key",
                "pattern": r"sk-ant-[a-zA-Z0-9\-]{32,}",
                "severity": "critical",
            },
            {
                "id": "stripe_live_key",
                "name": "Stripe Live API Key",
                "pattern": r"sk_live_[a-zA-Z0-9]{24,}",
                "severity": "critical",
            },
            {
                "id": "stripe_test_key",
                "name": "Stripe Test API Key",
                "pattern": r"sk_test_[a-zA-Z0-9]{24,}",
                "severity": "medium",
            },
            {
                "id": "generic_api_key",
                "name": "Generic API Key",
                "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?",
                "severity": "high",
            },
            {
                "id": "generic_secret",
                "name": "Generic Secret",
                "pattern": r"(?i)(secret|token|password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
                "severity": "high",
            },
            {
                "id": "private_key",
                "name": "Private Key",
                "pattern": r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
                "severity": "critical",
            },
            {
                "id": "jwt_token",
                "name": "JWT Token",
                "pattern": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
                "severity": "high",
            },
            {
                "id": "mongodb_uri",
                "name": "MongoDB Connection String",
                "pattern": r"mongodb(\+srv)?://[^\s]+",
                "severity": "critical",
            },
            {
                "id": "postgres_uri",
                "name": "PostgreSQL Connection String",
                "pattern": r"postgres(ql)?://[^\s]+",
                "severity": "critical",
            },
            {
                "id": "mysql_uri",
                "name": "MySQL Connection String",
                "pattern": r"mysql://[^\s]+",
                "severity": "critical",
            },
            {
                "id": "redis_uri",
                "name": "Redis Connection String",
                "pattern": r"redis://[^\s]+",
                "severity": "high",
            },
            {
                "id": "slack_token",
                "name": "Slack Token",
                "pattern": r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}",
                "severity": "critical",
            },
            {
                "id": "google_api_key",
                "name": "Google API Key",
                "pattern": r"AIza[0-9A-Za-z\-_]{35}",
                "severity": "critical",
            },
            {
                "id": "firebase_key",
                "name": "Firebase Key",
                "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
                "severity": "critical",
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
                # Skip invalid patterns
                continue

        await super().initialize()

    async def scan(
        self,
        text: str,
        context: str | None = None,
    ) -> ScannerResult:
        """Scan text for secrets.

        Args:
            text: Text to scan
            context: Unused for secrets scanner

        Returns:
            ScannerResult with findings
        """
        await self.ensure_initialized()

        findings: list[Finding] = []
        max_score = 0.0

        for pattern, pattern_def in self._compiled_patterns:
            for match in pattern.finditer(text):
                severity_str = pattern_def.get("severity", "medium")
                severity = Severity(severity_str)

                # Calculate score based on severity
                severity_scores = {
                    Severity.LOW: 0.3,
                    Severity.MEDIUM: 0.5,
                    Severity.HIGH: 0.7,
                    Severity.CRITICAL: 0.95,
                }
                score = severity_scores.get(severity, 0.5)
                max_score = max(max_score, score)

                # Mask the secret value for safe display
                matched_value = match.group()
                if len(matched_value) > 8:
                    masked = matched_value[:4] + "*" * (len(matched_value) - 8) + matched_value[-4:]
                else:
                    masked = "*" * len(matched_value)

                findings.append(
                    Finding(
                        type=pattern_def.get("id", "secret"),
                        value=masked,
                        location=(match.start(), match.end()),
                        severity=severity,
                        confidence=0.95,  # High confidence for regex matches
                        details={
                            "pattern_name": pattern_def.get("name", "Unknown"),
                            "original_length": len(matched_value),
                        },
                    )
                )

        return ScannerResult(
            score=max_score,
            findings=findings,
        )
