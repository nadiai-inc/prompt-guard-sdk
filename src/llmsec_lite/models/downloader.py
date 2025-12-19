"""Model downloader for LLMSEC LITE."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

# Model URLs - pointing to actual HuggingFace models
# Note: Using lightweight/optimized models for efficiency
MODEL_REGISTRY: dict[str, dict[str, Any]] = {
    "injection": {
        "filename": "injection_model.onnx",
        "url": "https://huggingface.co/testsavantai/prompt-injection-defender-small-v0-onnx/resolve/main/model.onnx",
        "size_mb": 115,
        "description": "Small BERT prompt injection detector (115 MB)",
    },
    "toxicity": {
        "filename": "toxic_model.onnx",
        "url": "https://huggingface.co/minuva/MiniLMv2-toxic-jigsaw-onnx/resolve/main/model_optimized_quantized.onnx",
        "size_mb": 23,
        "description": "MiniLMv2 toxic comment classifier (optimized INT8)",
    },
    "tokenizer": {
        "filename": "tokenizer.json",
        "url": "https://huggingface.co/testsavantai/prompt-injection-defender-small-v0-onnx/resolve/main/tokenizer.json",
        "size_mb": 1,
        "description": "BERT tokenizer (for injection scanner)",
    },
    "toxicity_tokenizer": {
        "filename": "toxicity_tokenizer.json",
        "url": "https://huggingface.co/minuva/MiniLMv2-toxic-jigsaw-onnx/resolve/main/tokenizer.json",
        "size_mb": 1,
        "description": "MiniLMv2 tokenizer (for toxicity scanner)",
    },
}


def get_cache_dir(cache_dir: str = "~/.llmsec-lite") -> Path:
    """Get the cache directory path.

    Args:
        cache_dir: Cache directory path (can include ~)

    Returns:
        Resolved Path object
    """
    path = Path(os.path.expanduser(cache_dir)) / "models"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_model_path(model_id: str, cache_dir: str = "~/.llmsec-lite") -> Path:
    """Get the path to a model file.

    Args:
        model_id: Model identifier (e.g., 'injection', 'toxicity')
        cache_dir: Cache directory path

    Returns:
        Path to the model file
    """
    if model_id not in MODEL_REGISTRY:
        raise ValueError(f"Unknown model: {model_id}")

    model_info = MODEL_REGISTRY[model_id]
    return get_cache_dir(cache_dir) / model_info["filename"]


async def download_model(
    model_id: str,
    cache_dir: str = "~/.llmsec-lite",
    force: bool = False,
) -> Path:
    """Download a model from the registry.

    Args:
        model_id: Model identifier
        cache_dir: Cache directory path
        force: Force re-download even if exists

    Returns:
        Path to the downloaded model
    """
    if model_id not in MODEL_REGISTRY:
        raise ValueError(f"Unknown model: {model_id}")

    model_info = MODEL_REGISTRY[model_id]
    model_path = get_model_path(model_id, cache_dir)

    # Check if already downloaded
    if model_path.exists() and not force:
        logger.debug("Model already cached", model_id=model_id, path=str(model_path))
        return model_path

    logger.info(
        "Downloading model",
        model_id=model_id,
        size_mb=model_info["size_mb"],
    )

    # Download the model
    url = model_info["url"]

    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            response = await client.get(url, follow_redirects=True)
            response.raise_for_status()

            # Write to file
            model_path.parent.mkdir(parents=True, exist_ok=True)
            with open(model_path, "wb") as f:
                f.write(response.content)

            logger.info(
                "Model downloaded successfully",
                model_id=model_id,
                path=str(model_path),
            )
            return model_path

        except httpx.HTTPError as e:
            logger.error(
                "Failed to download model",
                model_id=model_id,
                error=str(e),
            )
            raise


async def ensure_model_available(
    model_id: str,
    cache_dir: str = "~/.llmsec-lite",
    auto_download: bool = True,
) -> Path:
    """Ensure a model is available locally.

    Args:
        model_id: Model identifier
        cache_dir: Cache directory path
        auto_download: Whether to auto-download if missing

    Returns:
        Path to the model

    Raises:
        FileNotFoundError: If model not found and auto_download is False
    """
    model_path = get_model_path(model_id, cache_dir)

    if model_path.exists():
        return model_path

    if not auto_download:
        raise FileNotFoundError(
            f"Model '{model_id}' not found at {model_path}. "
            "Set auto_download=True or download manually."
        )

    return await download_model(model_id, cache_dir)


def list_cached_models(cache_dir: str = "~/.llmsec-lite") -> list[dict[str, Any]]:
    """List all cached models.

    Args:
        cache_dir: Cache directory path

    Returns:
        List of model info dicts
    """
    cache_path = get_cache_dir(cache_dir)
    cached = []

    for model_id, model_info in MODEL_REGISTRY.items():
        model_path = cache_path / model_info["filename"]
        cached.append({
            "model_id": model_id,
            "filename": model_info["filename"],
            "cached": model_path.exists(),
            "size_mb": model_info["size_mb"],
            "description": model_info["description"],
        })

    return cached


def clear_cache(cache_dir: str = "~/.llmsec-lite") -> int:
    """Clear all cached models.

    Args:
        cache_dir: Cache directory path

    Returns:
        Number of files deleted
    """
    cache_path = get_cache_dir(cache_dir)
    deleted = 0

    for model_path in cache_path.glob("*"):
        if model_path.is_file():
            model_path.unlink()
            deleted += 1

    return deleted
