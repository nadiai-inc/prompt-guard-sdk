"""Smart Router for LLMSEC LITE.

The router handles:
- Scanner on/off configuration
- Parallel execution (asyncio)
- Tiered processing (fast -> slow -> cloud)
- Early exit on critical threats
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

import structlog

from llmsec_lite.schemas.results import CheckResult, Finding, ScanResult, Severity

if TYPE_CHECKING:
    from llmsec_lite.scanners.base import BaseScanner
    from llmsec_lite.schemas.config import GuardConfig

logger = structlog.get_logger(__name__)


class ScannerTier(str, Enum):
    """Scanner tier for tiered processing."""

    FAST = "fast"  # Regex-based: ~2-5ms
    SLOW = "slow"  # ONNX models: ~20-30ms
    CLOUD = "cloud"  # LLM API calls: ~200-400ms


# Mapping of scanner IDs to their tiers
SCANNER_TIERS: dict[str, ScannerTier] = {
    "secrets": ScannerTier.FAST,
    "pii": ScannerTier.FAST,  # Regex part is fast
    "code_injection": ScannerTier.FAST,
    "injection": ScannerTier.SLOW,
    "toxicity": ScannerTier.SLOW,
    "hallucination": ScannerTier.CLOUD,
}


@dataclass
class RouterConfig:
    """Router configuration."""

    parallel: bool = True
    early_exit: bool = True
    fast_first: bool = True


@dataclass
class TierResult:
    """Result from processing a tier."""

    results: dict[str, CheckResult] = field(default_factory=dict)
    has_critical: bool = False
    latency_ms: float = 0.0


class SmartRouter:
    """Intelligent scanner router with tiered parallel execution."""

    def __init__(
        self,
        config: GuardConfig,
        scanners: dict[str, BaseScanner],
    ) -> None:
        """Initialize the router.

        Args:
            config: Guard configuration
            scanners: Dictionary of scanner_id -> scanner instance
        """
        self.config = config
        self.scanners = scanners
        self.router_config = RouterConfig(
            parallel=config.parallel,
            early_exit=config.early_exit,
        )

    def _get_enabled_scanners(
        self,
        direction: str,
        requested: list[str] | None = None,
    ) -> dict[str, BaseScanner]:
        """Get enabled scanners for a direction.

        Args:
            direction: 'input' or 'output'
            requested: Specific scanners to run (if None, use all enabled)

        Returns:
            Dictionary of enabled scanner_id -> scanner
        """
        enabled = {}

        for scanner_id, scanner in self.scanners.items():
            # Check if globally enabled in config
            if not self.config.is_scanner_enabled(scanner_id):
                continue

            # Check if scanner supports this direction
            scanner_direction = getattr(scanner, "direction", "both")
            if scanner_direction != "both" and scanner_direction != direction:
                continue

            # Check if specifically requested
            if requested and scanner_id not in requested:
                continue

            enabled[scanner_id] = scanner

        return enabled

    def _group_by_tier(
        self,
        scanners: dict[str, BaseScanner],
    ) -> dict[ScannerTier, dict[str, BaseScanner]]:
        """Group scanners by their tier.

        Args:
            scanners: Dictionary of scanner_id -> scanner

        Returns:
            Dictionary of tier -> {scanner_id: scanner}
        """
        groups: dict[ScannerTier, dict[str, BaseScanner]] = {
            ScannerTier.FAST: {},
            ScannerTier.SLOW: {},
            ScannerTier.CLOUD: {},
        }

        for scanner_id, scanner in scanners.items():
            tier = SCANNER_TIERS.get(scanner_id, ScannerTier.SLOW)
            groups[tier][scanner_id] = scanner

        return groups

    async def _run_scanner(
        self,
        scanner_id: str,
        scanner: BaseScanner,
        text: str,
        context: str | None = None,
    ) -> CheckResult:
        """Run a single scanner.

        Args:
            scanner_id: Scanner ID
            scanner: Scanner instance
            text: Text to scan
            context: Optional context (for hallucination)

        Returns:
            CheckResult from the scanner
        """
        start = time.perf_counter()
        try:
            # Run the scanner
            result = await scanner.scan(text, context=context)
            latency = (time.perf_counter() - start) * 1000

            # Determine if passed based on threshold
            threshold = self.config.get_threshold(scanner_id)
            passed = result.score < threshold

            return CheckResult(
                check_id=scanner_id,
                passed=passed,
                score=result.score,
                findings=result.findings,
                latency_ms=latency,
            )

        except Exception as e:
            latency = (time.perf_counter() - start) * 1000
            logger.warning(
                "Scanner failed, skipping",
                scanner_id=scanner_id,
                error=str(e),
            )
            # Fail open - return passing result
            return CheckResult(
                check_id=scanner_id,
                passed=True,
                score=0.0,
                findings=[],
                latency_ms=latency,
            )

    async def _run_tier(
        self,
        tier_scanners: dict[str, BaseScanner],
        text: str,
        context: str | None = None,
    ) -> TierResult:
        """Run all scanners in a tier.

        Args:
            tier_scanners: Scanners in this tier
            text: Text to scan
            context: Optional context

        Returns:
            TierResult with combined results
        """
        if not tier_scanners:
            return TierResult()

        start = time.perf_counter()

        if self.router_config.parallel:
            # Run in parallel
            tasks = [
                self._run_scanner(sid, scanner, text, context)
                for sid, scanner in tier_scanners.items()
            ]
            results = await asyncio.gather(*tasks)
            results_dict = {r.check_id: r for r in results}
        else:
            # Run serially
            results_dict = {}
            for scanner_id, scanner in tier_scanners.items():
                result = await self._run_scanner(scanner_id, scanner, text, context)
                results_dict[scanner_id] = result

        latency = (time.perf_counter() - start) * 1000

        # Check for critical findings
        has_critical = any(r.has_critical for r in results_dict.values())

        return TierResult(
            results=results_dict,
            has_critical=has_critical,
            latency_ms=latency,
        )

    def _is_critical_finding(self, finding: Finding) -> bool:
        """Check if a finding is critical enough for early exit."""
        return finding.severity == Severity.CRITICAL

    async def route(
        self,
        text: str,
        direction: str,
        context: str | None = None,
        checks: list[str] | None = None,
    ) -> ScanResult:
        """Route text through enabled scanners.

        Args:
            text: Text to scan
            direction: 'input' or 'output'
            context: Optional context (for hallucination on output)
            checks: Specific checks to run (if None, use all enabled)

        Returns:
            Combined ScanResult
        """
        start = time.perf_counter()

        # Get enabled scanners for this direction
        enabled_scanners = self._get_enabled_scanners(direction, checks)

        if not enabled_scanners:
            return ScanResult(
                blocked=False,
                risk_score=0.0,
                checks={},
                findings=[],
                sanitized_text=text,
                latency_ms=0.0,
            )

        # Group by tier
        tier_groups = self._group_by_tier(enabled_scanners)

        # Process tiers in order: fast -> slow -> cloud
        all_results: dict[str, CheckResult] = {}
        all_findings: list[Finding] = []
        should_exit = False

        for tier in [ScannerTier.FAST, ScannerTier.SLOW, ScannerTier.CLOUD]:
            if should_exit:
                break

            tier_scanners = tier_groups[tier]
            if not tier_scanners:
                continue

            tier_result = await self._run_tier(tier_scanners, text, context)
            all_results.update(tier_result.results)

            for check_result in tier_result.results.values():
                all_findings.extend(check_result.findings)

            # Check for early exit
            if self.router_config.early_exit and tier_result.has_critical:
                logger.info(
                    "Early exit due to critical threat",
                    tier=tier.value,
                )
                should_exit = True

        # Calculate overall risk score
        if all_results:
            risk_score = max(r.score for r in all_results.values())
        else:
            risk_score = 0.0

        # Determine if blocked
        blocked = any(not r.passed for r in all_results.values())

        latency = (time.perf_counter() - start) * 1000

        return ScanResult(
            blocked=blocked,
            risk_score=risk_score,
            checks=all_results,
            findings=all_findings,
            sanitized_text=text,  # Will be updated by PII scanner
            latency_ms=latency,
        )


def create_router(config: GuardConfig, scanners: dict[str, BaseScanner]) -> SmartRouter:
    """Create a configured router.

    Args:
        config: Guard configuration
        scanners: Dictionary of scanner_id -> scanner instance

    Returns:
        Configured SmartRouter instance
    """
    return SmartRouter(config, scanners)
