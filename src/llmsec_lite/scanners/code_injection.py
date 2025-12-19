"""Code injection scanner for LLMSEC LITE."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from llmsec_lite.scanners.base import RegexScanner, ScannerResult
from llmsec_lite.schemas.results import Finding, Severity


class CodeInjectionScanner(RegexScanner):
    """Scanner for detecting code injection patterns (SQL, XSS, Command injection)."""

    scanner_id = "code_injection"
    direction = "output"  # Primarily for scanning LLM outputs

    def __init__(self) -> None:
        """Initialize code injection scanner."""
        super().__init__()
        self._compiled_patterns: list[tuple[re.Pattern[str], dict[str, Any]]] = []

    async def _load_patterns(self) -> list[dict[str, Any]]:
        """Load code injection patterns from JSON file."""
        patterns_path = Path(__file__).parent.parent / "patterns" / "code_injection.json"

        if patterns_path.exists():
            with open(patterns_path) as f:
                data = json.load(f)
                return data.get("patterns", [])

        return self._get_default_patterns()

    def _get_default_patterns(self) -> list[dict[str, Any]]:
        """Get default code injection patterns."""
        return [
            # SQL Injection
            {
                "id": "sql_select",
                "name": "SQL SELECT Statement",
                "pattern": r"(?i)\bSELECT\b.+\bFROM\b",
                "severity": "medium",
                "category": "sql",
            },
            {
                "id": "sql_union",
                "name": "SQL UNION Injection",
                "pattern": r"(?i)\bUNION\s+(ALL\s+)?SELECT\b",
                "severity": "critical",
                "category": "sql",
            },
            {
                "id": "sql_drop",
                "name": "SQL DROP Statement",
                "pattern": r"(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\b",
                "severity": "critical",
                "category": "sql",
            },
            {
                "id": "sql_delete",
                "name": "SQL DELETE Statement",
                "pattern": r"(?i)\bDELETE\s+FROM\b",
                "severity": "high",
                "category": "sql",
            },
            {
                "id": "sql_insert",
                "name": "SQL INSERT Statement",
                "pattern": r"(?i)\bINSERT\s+INTO\b",
                "severity": "medium",
                "category": "sql",
            },
            {
                "id": "sql_update",
                "name": "SQL UPDATE Statement",
                "pattern": r"(?i)\bUPDATE\b.+\bSET\b",
                "severity": "medium",
                "category": "sql",
            },
            {
                "id": "sql_comment",
                "name": "SQL Comment Injection",
                "pattern": r";\s*--",
                "severity": "high",
                "category": "sql",
            },
            {
                "id": "sql_or_true",
                "name": "SQL OR 1=1 Injection",
                "pattern": r"(?i)\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
                "severity": "critical",
                "category": "sql",
            },
            {
                "id": "sql_and_true",
                "name": "SQL AND 1=1 Injection",
                "pattern": r"(?i)\bAND\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
                "severity": "high",
                "category": "sql",
            },
            {
                "id": "sql_truncate",
                "name": "SQL TRUNCATE Statement",
                "pattern": r"(?i)\bTRUNCATE\s+(TABLE\s+)?\w+",
                "severity": "critical",
                "category": "sql",
            },
            # XSS
            {
                "id": "xss_script",
                "name": "XSS Script Tag",
                "pattern": r"(?i)<script[^>]*>",
                "severity": "critical",
                "category": "xss",
            },
            {
                "id": "xss_javascript",
                "name": "XSS JavaScript Protocol",
                "pattern": r"(?i)javascript:",
                "severity": "critical",
                "category": "xss",
            },
            {
                "id": "xss_event_handler",
                "name": "XSS Event Handler",
                "pattern": r"(?i)\bon\w+\s*=",
                "severity": "high",
                "category": "xss",
            },
            {
                "id": "xss_iframe",
                "name": "XSS Iframe Tag",
                "pattern": r"(?i)<iframe[^>]*>",
                "severity": "high",
                "category": "xss",
            },
            {
                "id": "xss_embed",
                "name": "XSS Embed Tag",
                "pattern": r"(?i)<embed[^>]*>",
                "severity": "high",
                "category": "xss",
            },
            {
                "id": "xss_object",
                "name": "XSS Object Tag",
                "pattern": r"(?i)<object[^>]*>",
                "severity": "high",
                "category": "xss",
            },
            {
                "id": "xss_expression",
                "name": "XSS CSS Expression",
                "pattern": r"(?i)expression\s*\(",
                "severity": "high",
                "category": "xss",
            },
            {
                "id": "xss_vbscript",
                "name": "XSS VBScript Protocol",
                "pattern": r"(?i)vbscript:",
                "severity": "critical",
                "category": "xss",
            },
            # Command Injection
            {
                "id": "cmd_semicolon",
                "name": "Command Injection (Semicolon)",
                "pattern": r";\s*(rm|cat|ls|wget|curl|bash|sh|python|perl|ruby|chmod|chown|kill|pkill)\b",
                "severity": "critical",
                "category": "command",
            },
            {
                "id": "cmd_pipe",
                "name": "Command Injection (Pipe)",
                "pattern": r"\|\s*(bash|sh|zsh|cat|grep|awk|sed|python|perl)\b",
                "severity": "critical",
                "category": "command",
            },
            {
                "id": "cmd_backtick",
                "name": "Command Injection (Backtick)",
                "pattern": r"`[^`]+`",
                "severity": "high",
                "category": "command",
            },
            {
                "id": "cmd_subshell",
                "name": "Command Injection (Subshell)",
                "pattern": r"\$\([^)]+\)",
                "severity": "high",
                "category": "command",
            },
            {
                "id": "cmd_and",
                "name": "Command Injection (AND)",
                "pattern": r"&&\s*(rm|cat|wget|curl|bash|sh)\b",
                "severity": "critical",
                "category": "command",
            },
            {
                "id": "cmd_or",
                "name": "Command Injection (OR)",
                "pattern": r"\|\|\s*(rm|cat|wget|curl|bash|sh)\b",
                "severity": "critical",
                "category": "command",
            },
            # Path Traversal
            {
                "id": "path_traversal_unix",
                "name": "Path Traversal (Unix)",
                "pattern": r"\.\./",
                "severity": "high",
                "category": "path",
            },
            {
                "id": "path_traversal_windows",
                "name": "Path Traversal (Windows)",
                "pattern": r"\.\.\\",
                "severity": "high",
                "category": "path",
            },
            {
                "id": "path_etc_passwd",
                "name": "Path /etc/passwd",
                "pattern": r"/etc/passwd",
                "severity": "critical",
                "category": "path",
            },
            {
                "id": "path_etc_shadow",
                "name": "Path /etc/shadow",
                "pattern": r"/etc/shadow",
                "severity": "critical",
                "category": "path",
            },
            {
                "id": "path_windows_system",
                "name": "Windows System Path",
                "pattern": r"(?i)c:\\windows",
                "severity": "high",
                "category": "path",
            },
            # LDAP Injection
            {
                "id": "ldap_injection",
                "name": "LDAP Injection",
                "pattern": r"[()&|*\\]",
                "severity": "medium",
                "category": "ldap",
            },
            # XML Injection
            {
                "id": "xxe_entity",
                "name": "XXE Entity Declaration",
                "pattern": r"<!ENTITY\s+\w+\s+SYSTEM",
                "severity": "critical",
                "category": "xml",
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

    async def scan(
        self,
        text: str,
        context: str | None = None,
    ) -> ScannerResult:
        """Scan text for code injection patterns.

        Args:
            text: Text to scan
            context: Unused for code injection scanner

        Returns:
            ScannerResult with findings
        """
        await self.ensure_initialized()

        findings: list[Finding] = []
        max_score = 0.0
        categories_found: set[str] = set()

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

                category = pattern_def.get("category", "unknown")
                categories_found.add(category)

                matched_value = match.group()
                # Truncate long matches
                display_value = matched_value[:100] + "..." if len(matched_value) > 100 else matched_value

                findings.append(
                    Finding(
                        type=pattern_def.get("id", "code_injection"),
                        value=display_value,
                        location=(match.start(), match.end()),
                        severity=severity,
                        confidence=0.85,
                        details={
                            "pattern_name": pattern_def.get("name", "Unknown"),
                            "category": category,
                        },
                    )
                )

        return ScannerResult(
            score=max_score,
            findings=findings,
            metadata={"categories": list(categories_found)},
        )
