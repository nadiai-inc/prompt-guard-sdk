"""Tests for secrets scanner."""

import pytest

from llmsec_lite.scanners.secrets import SecretsScanner
from llmsec_lite.schemas.results import Severity


class TestSecretsScanner:
    """Tests for SecretsScanner."""

    @pytest.fixture
    def scanner(self) -> SecretsScanner:
        """Create a secrets scanner instance."""
        return SecretsScanner()

    @pytest.mark.asyncio
    async def test_detect_aws_access_key(self, scanner: SecretsScanner) -> None:
        """Test detection of AWS access keys."""
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) > 0
        assert any(f.type == "aws_access_key" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_openai_key(self, scanner: SecretsScanner) -> None:
        """Test detection of OpenAI API keys."""
        text = "My key is sk-1234567890abcdef1234567890abcdef1234567890abcdef"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) > 0
        assert any(f.type == "openai_key" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_github_token(self, scanner: SecretsScanner) -> None:
        """Test detection of GitHub tokens."""
        text = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) > 0
        assert any(f.type == "github_token" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_generic_password(self, scanner: SecretsScanner) -> None:
        """Test detection of generic passwords."""
        text = "password = MySecretPassword123!"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_detect_jwt_token(self, scanner: SecretsScanner) -> None:
        """Test detection of JWT tokens."""
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) > 0
        assert any(f.type == "jwt_token" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_mongodb_uri(self, scanner: SecretsScanner) -> None:
        """Test detection of MongoDB connection strings."""
        text = "MONGO_URI=mongodb://admin:password@localhost:27017/mydb"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_detect_private_key(self, scanner: SecretsScanner) -> None:
        """Test detection of private keys."""
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0m...
-----END RSA PRIVATE KEY-----"""
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    @pytest.mark.asyncio
    async def test_clean_text_no_secrets(self, scanner: SecretsScanner) -> None:
        """Test that clean text has no findings."""
        text = "This is a normal message without any secrets."
        result = await scanner.scan(text)

        assert result.score == 0.0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_masked_output(self, scanner: SecretsScanner) -> None:
        """Test that secret values are masked in findings."""
        text = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
        result = await scanner.scan(text)

        for finding in result.findings:
            # Value should be masked, not contain the full secret
            assert "*" in finding.value
            assert finding.value != text

    @pytest.mark.asyncio
    async def test_multiple_secrets(self, scanner: SecretsScanner) -> None:
        """Test detection of multiple secrets in one text."""
        text = """
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        password=secret123
        api_key=abc123def456ghi789
        """
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert len(result.findings) >= 2
