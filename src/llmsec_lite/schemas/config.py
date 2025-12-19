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

    LOCAL = "local"  # Only local scanners (no API calls)
    FULL = "full"  # Full mode with cloud scanners


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
        "injection": 0.8,
        "secrets": 0.9,
        "pii": 0.8,
        "toxicity": 0.7,
        "hallucination": 0.8,
        "code_injection": 0.9,
    },
    Sensitivity.BALANCED: {
        "injection": 0.6,
        "secrets": 0.7,
        "pii": 0.6,
        "toxicity": 0.5,
        "hallucination": 0.6,
        "code_injection": 0.7,
    },
    Sensitivity.STRICT: {
        "injection": 0.4,
        "secrets": 0.5,
        "pii": 0.4,
        "toxicity": 0.3,
        "hallucination": 0.4,
        "code_injection": 0.5,
    },
}


class ScannerConfig(BaseModel):
    """Configuration for individual scanner."""

    enabled: bool = Field(default=True, description="Whether scanner is enabled")
    threshold: float | None = Field(
        default=None, description="Custom threshold (overrides sensitivity)"
    )


class LLMConfig(BaseModel):
    """LLM configuration for hallucination detection."""

    provider: str = Field(default="openai", description="LLM provider (openai, azure, etc.)")
    model: str = Field(default="gpt-4o-mini", description="Model name")
    api_key: str | None = Field(default=None, description="API key (can be set separately)")
    base_url: str = Field(default="https://api.openai.com/v1", description="API base URL")
    timeout: int = Field(default=30, ge=1, le=120, description="Timeout in seconds")


class ScannersConfig(BaseModel):
    """Configuration for all scanners."""

    injection: ScannerConfig = Field(default_factory=ScannerConfig)
    toxicity: ScannerConfig = Field(default_factory=ScannerConfig)
    secrets: ScannerConfig = Field(default_factory=ScannerConfig)
    pii: ScannerConfig = Field(default_factory=ScannerConfig)
    code_injection: ScannerConfig = Field(default_factory=ScannerConfig)
    hallucination: ScannerConfig = Field(default_factory=ScannerConfig)


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
            "injection": {"enabled": true, "threshold": 0.3},
            "toxicity": {"enabled": true},
            "secrets": {"enabled": true},
            "pii": {"enabled": true},
            "code_injection": {"enabled": true},
            "hallucination": {"enabled": true, "threshold": 0.5}
        },
        "llm": {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "base_url": "https://api.openai.com/v1",
            "timeout": 30
        },
        "pii": {
            "redaction": true,
            "redaction_style": "full"
        },
        "mode": "local",
        "sensitivity": "balanced",
        "cache_dir": "~/.llmsec-lite"
    }
    """

    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    pii: PIIConfig = Field(default_factory=PIIConfig)
    mode: Mode = Field(default=Mode.LOCAL, description="Operating mode")
    sensitivity: Sensitivity = Field(default=Sensitivity.BALANCED, description="Threshold preset")
    cache_dir: str = Field(default="~/.llmsec-lite", description="Model cache directory")
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

    def to_guard_config(self, api_key: str | None = None) -> "GuardConfig":
        """Convert to GuardConfig for TrustGuard.

        Args:
            api_key: Optional API key (overrides config)

        Returns:
            GuardConfig instance
        """
        # Build thresholds dict only with non-None values
        thresholds = {}
        if self.scanners.injection.threshold is not None:
            thresholds["injection"] = self.scanners.injection.threshold
        if self.scanners.toxicity.threshold is not None:
            thresholds["toxicity"] = self.scanners.toxicity.threshold
        if self.scanners.secrets.threshold is not None:
            thresholds["secrets"] = self.scanners.secrets.threshold
        if self.scanners.pii.threshold is not None:
            thresholds["pii"] = self.scanners.pii.threshold
        if self.scanners.code_injection.threshold is not None:
            thresholds["code_injection"] = self.scanners.code_injection.threshold
        if self.scanners.hallucination.threshold is not None:
            thresholds["hallucination"] = self.scanners.hallucination.threshold

        return GuardConfig(
            api_key=api_key or self.llm.api_key,
            api_base_url=self.llm.base_url,
            api_timeout=self.llm.timeout,
            llm_model=self.llm.model,
            mode=self.mode,
            sensitivity=self.sensitivity,
            cache_dir=self.cache_dir,
            enable_injection=self.scanners.injection.enabled,
            enable_secrets=self.scanners.secrets.enabled,
            enable_pii=self.scanners.pii.enabled,
            enable_toxicity=self.scanners.toxicity.enabled,
            enable_hallucination=self.scanners.hallucination.enabled,
            enable_code_injection=self.scanners.code_injection.enabled,
            parallel=self.parallel,
            early_exit=self.early_exit,
            pii_redaction=self.pii.redaction,
            pii_redaction_style=self.pii.redaction_style,
            thresholds=thresholds if thresholds else None,
        )


class GuardConfig(BaseModel):
    """Configuration for TrustGuard."""

    # API Settings
    api_key: str | None = Field(default=None, description="OpenAI API key")
    api_base_url: str = Field(
        default="https://api.openai.com/v1", description="OpenAI API base URL"
    )
    api_timeout: int = Field(default=30, ge=1, le=120, description="API timeout in seconds")

    # LLM Model Settings (for hallucination detection)
    # Can be set via TRUSTGUARD_LLM environment variable
    llm_model: str = Field(
        default="gpt-4o-mini",
        description="LLM model for hallucination detection (e.g., gpt-4o-mini, gpt-4o, gpt-4-turbo, o3-mini)"
    )

    # Mode Settings
    mode: Mode = Field(default=Mode.LOCAL, description="Operating mode")
    sensitivity: Sensitivity = Field(default=Sensitivity.BALANCED, description="Threshold preset")

    # Model Settings
    auto_download: bool = Field(default=True, description="Download models on first use")
    cache_dir: str = Field(default="~/.llmsec-lite", description="Model cache directory")

    # Scanner Toggles
    enable_injection: bool = Field(default=True, description="Enable injection scanner")
    enable_secrets: bool = Field(default=True, description="Enable secrets scanner")
    enable_pii: bool = Field(default=True, description="Enable PII scanner")
    enable_toxicity: bool = Field(default=True, description="Enable toxicity scanner")
    enable_hallucination: bool = Field(
        default=True, description="Enable hallucination scanner (requires API key)"
    )
    enable_code_injection: bool = Field(default=True, description="Enable code injection scanner")

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

    def get_cache_path(self) -> Path:
        """Get resolved cache directory path."""
        return Path(os.path.expanduser(self.cache_dir))

    def is_scanner_enabled(self, scanner_id: str) -> bool:
        """Check if a scanner is enabled."""
        scanner_toggles = {
            "injection": self.enable_injection,
            "secrets": self.enable_secrets,
            "pii": self.enable_pii,
            "toxicity": self.enable_toxicity,
            "hallucination": self.enable_hallucination,
            "code_injection": self.enable_code_injection,
        }
        return scanner_toggles.get(scanner_id, False)

    @classmethod
    def from_env(cls) -> GuardConfig:
        """Load configuration from environment variables."""
        return cls(
            api_key=os.getenv("LLMSEC_API_KEY") or os.getenv("OPENAI_API_KEY"),
            api_base_url=os.getenv("LLMSEC_API_BASE_URL", "https://api.openai.com/v1"),
            llm_model=os.getenv("TRUSTGUARD_LLM", "gpt-4o-mini"),
            mode=Mode(os.getenv("LLMSEC_MODE", "local")),
            sensitivity=Sensitivity(os.getenv("LLMSEC_SENSITIVITY", "balanced")),
            cache_dir=os.getenv("LLMSEC_CACHE_DIR", "~/.llmsec-lite"),
            enable_injection=os.getenv("LLMSEC_ENABLE_INJECTION", "true").lower() == "true",
            enable_secrets=os.getenv("LLMSEC_ENABLE_SECRETS", "true").lower() == "true",
            enable_pii=os.getenv("LLMSEC_ENABLE_PII", "true").lower() == "true",
            enable_toxicity=os.getenv("LLMSEC_ENABLE_TOXICITY", "true").lower() == "true",
            enable_hallucination=os.getenv("LLMSEC_ENABLE_HALLUCINATION", "true").lower()
            == "true",
            enable_code_injection=os.getenv("LLMSEC_ENABLE_CODE_INJECTION", "true").lower()
            == "true",
            pii_redaction=os.getenv("LLMSEC_PII_REDACTION", "true").lower() == "true",
            pii_redaction_style=RedactionStyle(
                os.getenv("LLMSEC_PII_REDACTION_STYLE", "full")
            ),
        )


# Type alias for scanner direction
ScanDirection = Literal["input", "output", "both"]
