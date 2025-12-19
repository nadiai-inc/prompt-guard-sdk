"""Tests for PII scanner."""

import pytest

from llmsec_lite.scanners.pii import PIIScanner
from llmsec_lite.schemas.config import RedactionStyle
from llmsec_lite.schemas.results import Severity


class TestPIIScanner:
    """Tests for PIIScanner."""

    @pytest.fixture
    def scanner(self) -> PIIScanner:
        """Create a PII scanner instance."""
        return PIIScanner()

    @pytest.fixture
    def scanner_partial(self) -> PIIScanner:
        """Create a PII scanner with partial redaction."""
        return PIIScanner(redaction_style=RedactionStyle.PARTIAL)

    @pytest.mark.asyncio
    async def test_detect_ssn(self, scanner: PIIScanner) -> None:
        """Test detection of Social Security Numbers."""
        text = "My SSN is 123-45-6789"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) > 0
        assert any(f.type == "ssn" for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_credit_card_visa(self, scanner: PIIScanner) -> None:
        """Test detection of Visa credit cards."""
        text = "Card number: 4111111111111111"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) > 0
        assert any(f.type == "credit_card_visa" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_credit_card_mastercard(self, scanner: PIIScanner) -> None:
        """Test detection of Mastercard credit cards."""
        text = "Card: 5500000000000004"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "credit_card_mastercard" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_email(self, scanner: PIIScanner) -> None:
        """Test detection of email addresses."""
        text = "Contact me at john.doe@example.com"
        result = await scanner.scan(text)

        assert result.score > 0.0
        assert any(f.type == "email" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_phone_us(self, scanner: PIIScanner) -> None:
        """Test detection of US phone numbers."""
        text = "Call me at (555) 123-4567"
        result = await scanner.scan(text)

        assert len(result.findings) > 0
        assert any(f.type == "phone_us" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_ip_address(self, scanner: PIIScanner) -> None:
        """Test detection of IP addresses."""
        text = "Server IP: 192.168.1.100"
        result = await scanner.scan(text)

        assert len(result.findings) > 0
        assert any(f.type == "ip_address_v4" for f in result.findings)

    @pytest.mark.asyncio
    async def test_clean_text_no_pii(self, scanner: PIIScanner) -> None:
        """Test that clean text has no findings."""
        text = "Hello, how are you today?"
        result = await scanner.scan(text)

        assert result.score == 0.0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_redaction_full(self, scanner: PIIScanner) -> None:
        """Test full redaction style."""
        text = "My SSN is 123-45-6789"
        result = await scanner.scan(text)

        redacted = result.metadata.get("redacted_text")
        assert redacted is not None
        assert "[REDACTED]" in redacted
        assert "123-45-6789" not in redacted

    @pytest.mark.asyncio
    async def test_redaction_partial(self, scanner_partial: PIIScanner) -> None:
        """Test partial redaction style."""
        text = "My SSN is 123-45-6789"
        result = await scanner_partial.scan(text)

        redacted = result.metadata.get("redacted_text")
        assert redacted is not None
        assert "6789" in redacted  # Last 4 digits preserved
        assert "123-45-6789" not in redacted

    @pytest.mark.asyncio
    async def test_multiple_pii(self, scanner: PIIScanner) -> None:
        """Test detection of multiple PII in one text."""
        text = """
        Name: John Doe
        SSN: 123-45-6789
        Email: john@example.com
        Phone: 555-123-4567
        """
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) >= 3

    @pytest.mark.asyncio
    async def test_no_redaction(self) -> None:
        """Test scanner with redaction disabled."""
        scanner = PIIScanner(redaction_enabled=False)
        text = "My SSN is 123-45-6789"
        result = await scanner.scan(text)

        # Findings should still be detected
        assert len(result.findings) > 0
        # But redacted text should be None or same as original
        redacted = result.metadata.get("redacted_text")
        assert redacted is None
