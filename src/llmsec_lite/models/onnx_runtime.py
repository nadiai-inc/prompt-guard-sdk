"""ONNX runtime inference for LLMSEC LITE."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import numpy as np
import structlog

logger = structlog.get_logger(__name__)


class OnnxInference:
    """ONNX model inference wrapper."""

    def __init__(
        self,
        model_path: Path,
        tokenizer: Any = None,
    ) -> None:
        """Initialize ONNX inference.

        Args:
            model_path: Path to the ONNX model file
            tokenizer: Tokenizer instance
        """
        self.model_path = model_path
        self.tokenizer = tokenizer
        self._session = None

    def _load_session(self) -> None:
        """Load ONNX runtime session."""
        try:
            import onnxruntime as ort

            # Use CPU provider for lightweight operation
            providers = ["CPUExecutionProvider"]

            # Check if GPU is available and preferred
            if os.getenv("LLMSEC_USE_GPU", "false").lower() == "true":
                if "CUDAExecutionProvider" in ort.get_available_providers():
                    providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]

            sess_options = ort.SessionOptions()
            sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            sess_options.intra_op_num_threads = 4

            self._session = ort.InferenceSession(
                str(self.model_path),
                sess_options=sess_options,
                providers=providers,
            )

            logger.info(
                "ONNX session loaded",
                model=self.model_path.name,
                providers=self._session.get_providers(),
            )

        except ImportError:
            raise ImportError(
                "onnxruntime is required for ONNX model inference. "
                "Install with: pip install onnxruntime"
            )

    def ensure_loaded(self) -> None:
        """Ensure the session is loaded."""
        if self._session is None:
            self._load_session()

    def predict(
        self,
        text: str,
        max_length: int = 512,
    ) -> dict[str, np.ndarray]:
        """Run inference on text.

        Args:
            text: Input text
            max_length: Maximum sequence length

        Returns:
            Dictionary of output arrays
        """
        self.ensure_loaded()

        # Tokenize
        if self.tokenizer is None:
            raise ValueError("Tokenizer is required for text inference")

        encoding = self.tokenizer.encode(text)

        # Truncate if necessary
        if len(encoding.ids) > max_length:
            encoding.truncate(max_length)

        # Prepare inputs
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        # Get input names
        input_names = [inp.name for inp in self._session.get_inputs()]

        # Build input dict based on model requirements
        inputs = {}
        if "input_ids" in input_names:
            inputs["input_ids"] = input_ids
        if "attention_mask" in input_names:
            inputs["attention_mask"] = attention_mask
        if "token_type_ids" in input_names:
            token_type_ids = np.zeros_like(input_ids, dtype=np.int64)
            inputs["token_type_ids"] = token_type_ids

        # Run inference
        output_names = [out.name for out in self._session.get_outputs()]
        outputs = self._session.run(output_names, inputs)

        return dict(zip(output_names, outputs))

    def predict_batch(
        self,
        texts: list[str],
        max_length: int = 512,
        batch_size: int = 8,
    ) -> list[dict[str, np.ndarray]]:
        """Run inference on batch of texts.

        Args:
            texts: List of input texts
            max_length: Maximum sequence length
            batch_size: Batch size for inference

        Returns:
            List of output dictionaries
        """
        results = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            for text in batch:
                result = self.predict(text, max_length)
                results.append(result)
        return results


async def load_model(
    model_id: str,
    cache_dir: str = "~/.llmsec-lite",
    auto_download: bool = True,
) -> tuple[OnnxInference, Any]:
    """Load an ONNX model and its tokenizer.

    Args:
        model_id: Model identifier ('injection' or 'toxicity')
        cache_dir: Cache directory path
        auto_download: Whether to auto-download if missing

    Returns:
        Tuple of (OnnxInference instance, tokenizer)
    """
    from llmsec_lite.models.downloader import ensure_model_available

    # Ensure model is available
    model_path = await ensure_model_available(model_id, cache_dir, auto_download)

    # Load model-specific tokenizer
    tokenizer = await _load_tokenizer(model_id, cache_dir, auto_download)

    # Create inference instance
    inference = OnnxInference(model_path, tokenizer)

    return inference, tokenizer


async def _load_tokenizer(
    model_id: str = "injection",
    cache_dir: str = "~/.llmsec-lite",
    auto_download: bool = True,
) -> Any:
    """Load the tokenizer for a specific model.

    Args:
        model_id: Model identifier to select correct tokenizer
        cache_dir: Cache directory path
        auto_download: Whether to auto-download if missing

    Returns:
        Tokenizer instance
    """
    try:
        from tokenizers import Tokenizer

        from llmsec_lite.models.downloader import ensure_model_available

        # Use model-specific tokenizer
        if model_id == "toxicity":
            tokenizer_id = "toxicity_tokenizer"
        else:
            tokenizer_id = "tokenizer"  # Default DeBERTa tokenizer for injection

        tokenizer_path = await ensure_model_available(tokenizer_id, cache_dir, auto_download)
        return Tokenizer.from_file(str(tokenizer_path))

    except ImportError:
        raise ImportError(
            "tokenizers is required for ONNX model inference. "
            "Install with: pip install tokenizers"
        )


def softmax(x: np.ndarray) -> np.ndarray:
    """Compute softmax values for array x."""
    exp_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
    return exp_x / np.sum(exp_x, axis=-1, keepdims=True)


def sigmoid(x: np.ndarray) -> np.ndarray:
    """Compute sigmoid values for array x."""
    return 1 / (1 + np.exp(-x))
