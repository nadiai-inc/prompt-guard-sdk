"""Tests for TrustGuard main class."""

import pytest

from llmsec_lite import TrustGuard
from llmsec_lite.schemas.results import Severity


class TestTrustGuard:
    """Tests for TrustGuard main class."""

    @pytest.fixture
    def guard(self) -> TrustGuard:
        """Create a TrustGuard instance."""
        return TrustGuard(
            mode="local",
            enable_secrets=True,
            enable_pii=True,
        )

    # Input Scanning Tests

    @pytest.mark.asyncio
    async def test_scan_input_clean(self, guard: TrustGuard) -> None:
        """Test scanning clean input."""
        result = await guard.scan_input_async("Tell me a joke about programming.")

        assert not result.blocked
        assert result.risk_score < 0.5
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_scan_input_with_secrets(self, guard: TrustGuard) -> None:
        """Test scanning input with secrets."""
        text = "My API key is sk-1234567890abcdef1234567890abcdef1234567890abcdef"
        result = await guard.scan_input_async(text)

        assert result.blocked or result.risk_score > 0.5
        assert len(result.findings) > 0
        assert "secrets" in result.checks

    @pytest.mark.asyncio
    async def test_scan_input_with_pii(self, guard: TrustGuard) -> None:
        """Test scanning input with PII."""
        text = "My SSN is 123-45-6789"
        result = await guard.scan_input_async(text)

        assert result.risk_score > 0.5
        assert len(result.findings) > 0
        assert "pii" in result.checks

    # Output Scanning Tests

    @pytest.mark.asyncio
    async def test_scan_output_clean(self, guard: TrustGuard) -> None:
        """Test scanning clean output."""
        result = await guard.scan_output_async("Here is your joke: Why do programmers prefer dark mode?")

        assert not result.blocked
        assert result.risk_score < 0.5

    @pytest.mark.asyncio
    async def test_scan_output_pii_redaction(self, guard: TrustGuard) -> None:
        """Test that PII is redacted in output."""
        text = "The customer's SSN is 123-45-6789"
        result = await guard.scan_output_async(text)

        assert result.sanitized_text is not None
        assert "123-45-6789" not in result.sanitized_text

    # Full Scan Tests

    @pytest.mark.asyncio
    async def test_scan_both(self, guard: TrustGuard) -> None:
        """Test scanning both input and output."""
        input_text = "What is my account balance?"
        output_text = "Your account balance is $1,234.56"

        result = await guard.scan_async(input_text, output_text)

        assert not result.blocked
        assert result.input_result is not None
        assert result.output_result is not None

    @pytest.mark.asyncio
    async def test_scan_both_blocked(self, guard: TrustGuard) -> None:
        """Test full scan with blocked content."""
        input_text = "My API key is sk-1234567890abcdef1234567890abcdef1234567890abcdef"
        output_text = "Here's the response"

        result = await guard.scan_async(input_text, output_text)

        assert result.blocked
        assert result.block_reason is not None
        assert "input" in result.block_reason.lower() or "secrets" in result.block_reason.lower()

    # Configuration Tests

    def test_scanner_toggles(self) -> None:
        """Test that scanner toggles work correctly."""
        guard = TrustGuard(
            enable_secrets=True,
            enable_pii=False,
        )

        info = guard.get_scanner_info()
        assert "secrets" in info
        assert "pii" not in info

    def test_sensitivity_levels(self) -> None:
        """Test different sensitivity levels."""
        guard_low = TrustGuard(sensitivity="low")
        guard_strict = TrustGuard(sensitivity="strict")

        # Strict should have lower thresholds (more sensitive)
        assert guard_strict.config.get_threshold("secrets") < guard_low.config.get_threshold("secrets")

    def test_from_env(self) -> None:
        """Test creating TrustGuard from environment."""
        import os

        # Set env vars
        old_mode = os.environ.get("LLMSEC_MODE")
        os.environ["LLMSEC_MODE"] = "local"

        try:
            guard = TrustGuard.from_env()
            assert guard.config.mode.value == "local"
        finally:
            # Restore
            if old_mode:
                os.environ["LLMSEC_MODE"] = old_mode
            else:
                os.environ.pop("LLMSEC_MODE", None)

    # Specific Checks Tests

    @pytest.mark.asyncio
    async def test_specific_checks(self, guard: TrustGuard) -> None:
        """Test running only specific checks."""
        text = "My SSN is 123-45-6789 and my API key is sk-1234567890abcdef1234567890abcdef1234567890abcdef"

        # Only run PII check
        result = await guard.scan_input_async(text, checks=["pii"])

        assert "pii" in result.checks
        assert any(f.type == "ssn" for f in result.findings)

    # Edge Cases

    @pytest.mark.asyncio
    async def test_empty_text(self, guard: TrustGuard) -> None:
        """Test scanning empty text."""
        result = await guard.scan_input_async("")

        assert not result.blocked
        assert result.risk_score == 0.0

    @pytest.mark.asyncio
    async def test_very_long_text(self, guard: TrustGuard) -> None:
        """Test scanning very long text."""
        text = "This is a normal sentence. " * 1000
        result = await guard.scan_input_async(text)

        assert not result.blocked

    @pytest.mark.asyncio
    async def test_unicode_text(self, guard: TrustGuard) -> None:
        """Test scanning text with unicode characters."""
        text = "Hello 你好 مرحبا שלום 🎉"
        result = await guard.scan_input_async(text)

        assert not result.blocked

    @pytest.mark.asyncio
    async def test_reasons_property(self, guard: TrustGuard) -> None:
        """Test that reasons property works correctly."""
        text = "My SSN is 123-45-6789"
        result = await guard.scan_input_async(text)

        if result.blocked or result.risk_score > 0.5:
            assert len(result.reasons) > 0
            assert any("pii" in reason.lower() or "ssn" in reason.lower() for reason in result.reasons)

    # Sync API Tests

    def test_sync_scan_input(self, guard: TrustGuard) -> None:
        """Test synchronous scan_input method."""
        result = guard.scan_input("Hello, world!")

        assert not result.blocked
        assert result.latency_ms >= 0

    def test_sync_scan_output(self, guard: TrustGuard) -> None:
        """Test synchronous scan_output method."""
        result = guard.scan_output("Here is your response.")

        assert not result.blocked
        assert result.latency_ms >= 0

    def test_sync_scan(self, guard: TrustGuard) -> None:
        """Test synchronous full scan method."""
        result = guard.scan(
            input_text="What time is it?",
            output_text="The time is 3:00 PM."
        )

        assert not result.blocked
        assert result.latency_ms >= 0
