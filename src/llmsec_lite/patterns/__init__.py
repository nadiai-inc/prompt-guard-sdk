"""Pattern files for LLMSEC LITE scanners."""

from pathlib import Path

PATTERNS_DIR = Path(__file__).parent


def get_pattern_file(name: str) -> Path:
    """Get path to a pattern file.

    Args:
        name: Pattern file name (without .json extension)

    Returns:
        Path to the pattern file
    """
    return PATTERNS_DIR / f"{name}.json"
