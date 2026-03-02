"""Configuration schemas for LLMSEC LITE."""

from __future__ import annotations

import json
import os
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class Mode(str, Enum):
    """Operating mode."""

    LOCAL = "local"
    FULL = "full"


class Sensitivity(str, Enum):
    """Sensitivity/threshold presets."""

    LOW = "low"  # Fewer false positives, may miss some threats
    BALANCED = "balanced"  # Default balanced approach
    STRICT = "strict"  # More sensitive, may have false positives


class RedactionStyle(str, Enum):
    """PII redaction style."""

    FULL = "full"  # [REDACTED]
    PARTIAL = "partial"  # ***-**-1234
    HASH = "hash"  # [PII:a3f2...]


# Default thresholds per sensitivity level
SENSITIVITY_THRESHOLDS: dict[Sensitivity, dict[str, float]] = {
    Sensitivity.LOW: {
        "secrets": 0.9,
        "pii": 0.8,
    },
    Sensitivity.BALANCED: {
        "secrets": 0.7,
        "pii": 0.6,
    },
    Sensitivity.STRICT: {
        "secrets": 0.5,
        "pii": 0.4,
    },
}


class ScannerConfig(BaseModel):
    """Configuration for individual scanner."""

    enabled: bool = Field(default=True, description="Whether scanner is enabled")
    threshold: float | None = Field(
        default=None, description="Custom threshold (overrides sensitivity)"
    )


class ScannersConfig(BaseModel):
    """Configuration for all scanners."""

    secrets: ScannerConfig = Field(default_factory=ScannerConfig)
    pii: ScannerConfig = Field(default_factory=ScannerConfig)


class PIIConfig(BaseModel):
    """PII-specific configuration."""

    redaction: bool = Field(default=True, description="Enable PII redaction")
    redaction_style: RedactionStyle = Field(default=RedactionStyle.FULL, description="Redaction style")


class LLMSecLiteConfig(BaseModel):
    """
    Main configuration for LLMSEC LITE SDK.

    This config can be:
    - Loaded from a JSON file (llmsec_lite.config.json)
    - Passed as a dict from a database
    - Created programmatically

    Example JSON:
    {
        "scanners": {
            "secrets": {"enabled": true},
            "pii": {"enabled": true}
        },
        "pii": {
            "redaction": true,
            "redaction_style": "full"
        },
        "mode": "local",
        "sensitivity": "balanced"
    }
    """

    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    pii: PIIConfig = Field(default_factory=PIIConfig)
    mode: Mode = Field(default=Mode.LOCAL, description="Operating mode")
    sensitivity: Sensitivity = Field(default=Sensitivity.BALANCED, description="Threshold preset")
    parallel: bool = Field(default=True, description="Run scanners in parallel")
    early_exit: bool = Field(default=True, description="Stop on critical threat")

    @classmethod
    def from_file(cls, path: str | Path) -> "LLMSecLiteConfig":
        """Load configuration from a JSON file.

        Args:
            path: Path to the config file (e.g., 'llmsec_lite.config.json')

        Returns:
            LLMSecLiteConfig instance
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path) as f:
            data = json.load(f)

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LLMSecLiteConfig":
        """Load configuration from a dictionary.

        This is the primary method for loading config from a database.

        Args:
            data: Configuration dictionary

        Returns:
            LLMSecLiteConfig instance

        Example:
            # From database
            config_data = db.get_org_config(org_id)
            config = LLMSecLiteConfig.from_dict(config_data)
        """
        return cls.model_validate(data)

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to a dictionary.

        Useful for storing in a database.

        Returns:
            Configuration as a dictionary
        """
        return self.model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        """Convert configuration to a JSON string.

        Args:
            indent: JSON indentation

        Returns:
            JSON string
        """
        return json.dumps(self.to_dict(), indent=indent)

    def save_to_file(self, path: str | Path) -> None:
        """Save configuration to a JSON file.

        Args:
            path: Path to save the config file
        """
        path = Path(path)
        with open(path, "w") as f:
            f.write(self.to_json())

    def to_guard_config(self) -> "GuardConfig":
        """Convert to GuardConfig for TrustGuard.

        Returns:
            GuardConfig instance
        """
        # Build thresholds dict only with non-None values
        thresholds = {}
        if self.scanners.secrets.threshold is not None:
            thresholds["secrets"] = self.scanners.secrets.threshold
        if self.scanners.pii.threshold is not None:
            thresholds["pii"] = self.scanners.pii.threshold

        return GuardConfig(
            mode=self.mode,
            sensitivity=self.sensitivity,
            enable_secrets=self.scanners.secrets.enabled,
            enable_pii=self.scanners.pii.enabled,
            parallel=self.parallel,
            early_exit=self.early_exit,
            pii_redaction=self.pii.redaction,
            pii_redaction_style=self.pii.redaction_style,
            thresholds=thresholds if thresholds else None,
        )


class GuardConfig(BaseModel):
    """Configuration for TrustGuard."""

    # Mode Settings
    mode: Mode = Field(default=Mode.LOCAL, description="Operating mode")
    sensitivity: Sensitivity = Field(default=Sensitivity.BALANCED, description="Threshold preset")

    # Scanner Toggles
    enable_secrets: bool = Field(default=True, description="Enable secrets scanner")
    enable_pii: bool = Field(default=True, description="Enable PII scanner")

    # Router Settings
    parallel: bool = Field(default=True, description="Run scanners in parallel")
    early_exit: bool = Field(default=True, description="Stop on critical threat")

    # PII Settings
    pii_redaction: bool = Field(default=True, description="Enable PII redaction")
    pii_redaction_style: RedactionStyle = Field(
        default=RedactionStyle.FULL, description="Redaction style"
    )

    # Custom Thresholds (override sensitivity defaults)
    thresholds: dict[str, float] | None = Field(
        default=None, description="Custom thresholds per scanner"
    )

    def get_threshold(self, scanner_id: str) -> float:
        """Get threshold for a scanner."""
        if self.thresholds and scanner_id in self.thresholds:
            return self.thresholds[scanner_id]
        return SENSITIVITY_THRESHOLDS[self.sensitivity].get(scanner_id, 0.5)

    def is_scanner_enabled(self, scanner_id: str) -> bool:
        """Check if a scanner is enabled."""
        scanner_toggles = {
            "secrets": self.enable_secrets,
            "pii": self.enable_pii,
        }
        return scanner_toggles.get(scanner_id, False)

    @classmethod
    def from_env(cls) -> GuardConfig:
        """Load configuration from environment variables."""
        return cls(
            mode=Mode(os.getenv("LLMSEC_MODE", "local")),
            sensitivity=Sensitivity(os.getenv("LLMSEC_SENSITIVITY", "balanced")),
            enable_secrets=os.getenv("LLMSEC_ENABLE_SECRETS", "true").lower() == "true",
            enable_pii=os.getenv("LLMSEC_ENABLE_PII", "true").lower() == "true",
            pii_redaction=os.getenv("LLMSEC_PII_REDACTION", "true").lower() == "true",
            pii_redaction_style=RedactionStyle(
                os.getenv("LLMSEC_PII_REDACTION_STYLE", "full")
            ),
        )


# Type alias for scanner direction
ScanDirection = Literal["input", "output", "both"]
