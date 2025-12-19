"""Tests for code injection scanner."""

import pytest

from llmsec_lite.scanners.code_injection import CodeInjectionScanner
from llmsec_lite.schemas.results import Severity


class TestCodeInjectionScanner:
    """Tests for CodeInjectionScanner."""

    @pytest.fixture
    def scanner(self) -> CodeInjectionScanner:
        """Create a code injection scanner instance."""
        return CodeInjectionScanner()

    # SQL Injection Tests

    @pytest.mark.asyncio
    async def test_detect_sql_select(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of SQL SELECT statements."""
        text = "SELECT * FROM users WHERE id = 1"
        result = await scanner.scan(text)

        assert result.score > 0.0
        assert any(f.type == "sql_select" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_sql_union(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of SQL UNION injection."""
        text = "' UNION SELECT password FROM admin --"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "sql_union" for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_sql_drop(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of SQL DROP statements."""
        text = "DROP TABLE users"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "sql_drop" for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_sql_or_true(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of SQL OR 1=1."""
        text = "' OR 1=1 --"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "sql_or_true" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_sql_comment(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of SQL comment injection."""
        text = "admin'; --"
        result = await scanner.scan(text)

        assert len(result.findings) > 0
        assert any(f.type == "sql_comment" for f in result.findings)

    # XSS Tests

    @pytest.mark.asyncio
    async def test_detect_xss_script(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of XSS script tags."""
        text = "<script>alert('xss')</script>"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "xss_script" for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_xss_javascript(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of javascript: protocol."""
        text = '<a href="javascript:alert(1)">click</a>'
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "xss_javascript" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_xss_event_handler(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of XSS event handlers."""
        text = '<img src="x" onerror="alert(1)">'
        result = await scanner.scan(text)

        assert len(result.findings) > 0
        assert any(f.type == "xss_event_handler" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_xss_iframe(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of iframe injection."""
        text = '<iframe src="http://evil.com"></iframe>'
        result = await scanner.scan(text)

        assert len(result.findings) > 0
        assert any(f.type == "xss_iframe" for f in result.findings)

    # Command Injection Tests

    @pytest.mark.asyncio
    async def test_detect_cmd_semicolon(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of command injection via semicolon."""
        text = "; rm -rf /"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "cmd_semicolon" for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_cmd_pipe(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of command injection via pipe."""
        text = "| bash -c 'echo pwned'"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "cmd_pipe" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_cmd_backtick(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of command injection via backticks."""
        text = "`whoami`"
        result = await scanner.scan(text)

        assert len(result.findings) > 0
        assert any(f.type == "cmd_backtick" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_cmd_subshell(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of command injection via subshell."""
        text = "$(cat /etc/passwd)"
        result = await scanner.scan(text)

        assert len(result.findings) > 0
        assert any(f.type == "cmd_subshell" for f in result.findings)

    # Path Traversal Tests

    @pytest.mark.asyncio
    async def test_detect_path_traversal(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of path traversal."""
        text = "../../../etc/passwd"
        result = await scanner.scan(text)

        assert len(result.findings) > 0
        assert any(f.type == "path_traversal_unix" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detect_etc_passwd(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of /etc/passwd access."""
        text = "cat /etc/passwd"
        result = await scanner.scan(text)

        assert result.score > 0.5
        assert any(f.type == "path_etc_passwd" for f in result.findings)

    # Clean Text Tests

    @pytest.mark.asyncio
    async def test_clean_code_example(self, scanner: CodeInjectionScanner) -> None:
        """Test that educational code examples are detected but categorized."""
        text = "Here's an example SELECT query for educational purposes"
        result = await scanner.scan(text)

        # May detect SELECT but should have lower severity
        assert result.score < 0.9

    @pytest.mark.asyncio
    async def test_clean_text_no_injection(self, scanner: CodeInjectionScanner) -> None:
        """Test that clean text has no critical findings."""
        text = "Please help me write a function to sort an array."
        result = await scanner.scan(text)

        assert result.score == 0.0
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_multiple_injection_types(self, scanner: CodeInjectionScanner) -> None:
        """Test detection of multiple injection types."""
        text = """
        SELECT * FROM users; DROP TABLE users;--
        <script>alert('xss')</script>
        ; rm -rf /
        """
        result = await scanner.scan(text)

        assert result.score > 0.5
        categories = result.metadata.get("categories", [])
        assert "sql" in categories
        assert "xss" in categories
        assert "command" in categories
