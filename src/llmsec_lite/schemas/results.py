"""Result schemas for LLMSEC LITE."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """Individual security finding."""

    type: str = Field(..., description="Type of finding (e.g., 'injection', 'pii', 'secret')")
    value: str = Field(..., description="The detected content")
    location: tuple[int, int] = Field(..., description="(start, end) position in text")
    severity: Severity = Field(..., description="Severity level of the finding")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    details: dict[str, Any] | None = Field(default=None, description="Additional context")

    class Config:
        """Pydantic config."""

        frozen = True


class CheckResult(BaseModel):
    """Result of a single guard rail check."""

    check_id: str = Field(..., description="Scanner ID (e.g., 'injection', 'pii')")
    passed: bool = Field(..., description="Whether this check passed")
    score: float = Field(..., ge=0.0, le=1.0, description="Risk score 0.0-1.0")
    findings: list[Finding] = Field(default_factory=list, description="What was found")
    latency_ms: float = Field(..., ge=0.0, description="Processing time in milliseconds")

    @property
    def blocked(self) -> bool:
        """Whether this check should block the request."""
        return not self.passed

    @property
    def has_critical(self) -> bool:
        """Whether this check has critical findings."""
        return any(f.severity == Severity.CRITICAL for f in self.findings)


class ScanResult(BaseModel):
    """Result of scanning text."""

    blocked: bool = Field(..., description="Whether this should be blocked")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall risk 0.0-1.0")
    checks: dict[str, CheckResult] = Field(
        default_factory=dict, description="Results per guard rail"
    )
    findings: list[Finding] = Field(default_factory=list, description="All findings combined")
    sanitized_text: str | None = Field(default=None, description="Text with PII redacted")
    latency_ms: float = Field(..., ge=0.0, description="Total processing time")

    @property
    def reasons(self) -> list[str]:
        """List of reasons for blocking."""
        reasons = []
        for check_id, result in self.checks.items():
            if not result.passed:
                for finding in result.findings:
                    reasons.append(
                        f"{check_id}: {finding.type} ({finding.severity.value}) - {finding.value[:50]}..."
                        if len(finding.value) > 50
                        else f"{check_id}: {finding.type} ({finding.severity.value}) - {finding.value}"
                    )
        return reasons

    @property
    def has_critical(self) -> bool:
        """Whether any check has critical findings."""
        return any(check.has_critical for check in self.checks.values())

    def get_check(self, check_id: str) -> CheckResult | None:
        """Get a specific check result."""
        return self.checks.get(check_id)


class FullScanResult(BaseModel):
    """Result of scanning both input and output."""

    input_result: ScanResult = Field(..., description="Input scan result")
    output_result: ScanResult = Field(..., description="Output scan result")
    blocked: bool = Field(..., description="Whether either is blocked")
    block_reason: str | None = Field(default=None, description="Why blocked")
    latency_ms: float = Field(..., ge=0.0, description="Total time")

    @classmethod
    def from_results(
        cls,
        input_result: ScanResult,
        output_result: ScanResult,
        latency_ms: float,
    ) -> FullScanResult:
        """Create from input and output results."""
        blocked = input_result.blocked or output_result.blocked
        block_reason = None
        if blocked:
            reasons = []
            if input_result.blocked:
                reasons.extend([f"input: {r}" for r in input_result.reasons])
            if output_result.blocked:
                reasons.extend([f"output: {r}" for r in output_result.reasons])
            block_reason = "; ".join(reasons)

        return cls(
            input_result=input_result,
            output_result=output_result,
            blocked=blocked,
            block_reason=block_reason,
            latency_ms=latency_ms,
        )
