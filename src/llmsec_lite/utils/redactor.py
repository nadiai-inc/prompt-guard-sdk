"""Text redaction utilities for LLMSEC LITE."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from llmsec_lite.schemas.config import RedactionStyle


@dataclass
class RedactionResult:
    """Result of redaction operation."""

    original_text: str
    redacted_text: str
    redactions: list[dict[str, Any]] = field(default_factory=list)
    redaction_count: int = 0

    @property
    def was_modified(self) -> bool:
        """Whether the text was modified."""
        return self.original_text != self.redacted_text


class Redactor:
    """Text redaction utility.

    Supports multiple redaction styles:
    - FULL: Replace with [REDACTED]
    - PARTIAL: Mask with asterisks, keep last few chars
    - HASH: Replace with hash of original value
    """

    def __init__(
        self,
        style: RedactionStyle = RedactionStyle.FULL,
        placeholder: str = "[REDACTED]",
    ) -> None:
        """Initialize redactor.

        Args:
            style: Redaction style to use
            placeholder: Placeholder text for FULL style
        """
        self.style = style
        self.placeholder = placeholder

    def redact(
        self,
        text: str,
        matches: list[tuple[int, int, str, dict[str, Any]]],
    ) -> RedactionResult:
        """Redact matched content from text.

        Args:
            text: Original text
            matches: List of (start, end, type, details) tuples

        Returns:
            RedactionResult with redacted text
        """
        if not matches:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                redactions=[],
                redaction_count=0,
            )

        # Sort matches by position (reverse to maintain offsets)
        sorted_matches = sorted(matches, key=lambda m: m[0], reverse=True)

        redacted_text = text
        redactions = []

        for start, end, match_type, details in sorted_matches:
            original_value = text[start:end]
            redacted_value = self._redact_value(original_value, match_type, details)

            redacted_text = redacted_text[:start] + redacted_value + redacted_text[end:]

            redactions.append({
                "type": match_type,
                "start": start,
                "end": end,
                "original_length": len(original_value),
                "redacted_value": redacted_value,
                "details": details,
            })

        return RedactionResult(
            original_text=text,
            redacted_text=redacted_text,
            redactions=redactions,
            redaction_count=len(redactions),
        )

    def _redact_value(
        self,
        value: str,
        match_type: str,
        details: dict[str, Any],
    ) -> str:
        """Redact a single value.

        Args:
            value: Original value
            match_type: Type of the match (e.g., 'ssn', 'email')
            details: Additional match details

        Returns:
            Redacted string
        """
        if self.style == RedactionStyle.FULL:
            return self.placeholder

        if self.style == RedactionStyle.HASH:
            hash_val = hashlib.sha256(value.encode()).hexdigest()[:8]
            return f"[{match_type.upper()}:{hash_val}]"

        # PARTIAL style
        return self._partial_redact(value, match_type, details)

    def _partial_redact(
        self,
        value: str,
        match_type: str,
        details: dict[str, Any],
    ) -> str:
        """Apply partial redaction based on match type.

        Args:
            value: Original value
            match_type: Type of the match
            details: Additional match details

        Returns:
            Partially redacted string
        """
        # Get template from details if available
        template = details.get("redaction_partial")
        if template:
            return self._apply_template(value, template)

        # Default partial redaction logic
        length = len(value)

        # Keep last 4 characters for most types
        if length <= 4:
            return "*" * length

        # SSN: ***-**-1234
        if match_type in ["ssn"]:
            return f"***-**-{value[-4:]}"

        # Credit cards: ****-****-****-1234
        if match_type.startswith("credit_card"):
            return f"****-****-****-{value[-4:]}"

        # Phone: (***) ***-1234
        if match_type.startswith("phone"):
            return f"(***) ***-{value[-4:]}"

        # Email: j***@***.***
        if match_type == "email":
            at_idx = value.find("@")
            if at_idx > 0:
                return f"{value[0]}***@***.***"
            return f"{value[0]}***"

        # Default: show first and last 2 chars
        if length > 6:
            return f"{value[:2]}{'*' * (length - 4)}{value[-2:]}"

        return "*" * (length - 2) + value[-2:]

    def _apply_template(self, value: str, template: str) -> str:
        """Apply a redaction template.

        Args:
            value: Original value
            template: Template string with placeholders

        Returns:
            Redacted string using template
        """
        result = template

        # {last4} - last 4 characters
        if "{last4}" in result and len(value) >= 4:
            result = result.replace("{last4}", value[-4:])

        # {first} - first character
        if "{first}" in result and len(value) >= 1:
            result = result.replace("{first}", value[0])

        # {first_char} - same as {first}
        if "{first_char}" in result and len(value) >= 1:
            result = result.replace("{first_char}", value[0])

        return result

    def redact_pattern(
        self,
        text: str,
        pattern: str | re.Pattern[str],
        match_type: str = "pattern",
    ) -> RedactionResult:
        """Redact all matches of a pattern.

        Args:
            text: Text to redact
            pattern: Regex pattern to match
            match_type: Type name for the matches

        Returns:
            RedactionResult with redacted text
        """
        if isinstance(pattern, str):
            pattern = re.compile(pattern)

        matches = []
        for match in pattern.finditer(text):
            matches.append((
                match.start(),
                match.end(),
                match_type,
                {},
            ))

        return self.redact(text, matches)


def create_redactor(
    style: str = "full",
    placeholder: str = "[REDACTED]",
) -> Redactor:
    """Create a redactor instance.

    Args:
        style: Redaction style ('full', 'partial', 'hash')
        placeholder: Placeholder for full redaction

    Returns:
        Configured Redactor instance
    """
    return Redactor(
        style=RedactionStyle(style),
        placeholder=placeholder,
    )
