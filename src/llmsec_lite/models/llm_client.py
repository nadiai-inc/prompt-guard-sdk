"""LLM client for LLMSEC LITE."""

from __future__ import annotations

import os
from typing import Any

import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

logger = structlog.get_logger(__name__)


class LLMClient:
    """Wrapper for OpenAI API client."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        timeout: int = 30,
    ) -> None:
        """Initialize LLM client.

        Args:
            api_key: OpenAI API key (or from env LLMSEC_API_KEY)
            base_url: API base URL
            model: Model to use
            timeout: Request timeout in seconds
        """
        self.api_key = api_key or os.getenv("LLMSEC_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.base_url = base_url
        self.model = model
        self.timeout = timeout
        self._client = None

    def _ensure_client(self) -> None:
        """Ensure OpenAI client is initialized."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI

                if not self.api_key:
                    raise ValueError(
                        "API key required. Set LLMSEC_API_KEY or OPENAI_API_KEY environment variable, "
                        "or pass api_key parameter."
                    )

                self._client = AsyncOpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                    timeout=self.timeout,
                )

            except ImportError:
                raise ImportError(
                    "openai is required for LLM operations. "
                    "Install with: pip install openai"
                )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    async def complete(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> str:
        """Get a completion from the LLM.

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            Completion text
        """
        self._ensure_client()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            response = await self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            return response.choices[0].message.content or ""

        except Exception as e:
            logger.error("LLM completion failed", error=str(e))
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    async def complete_json(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> dict[str, Any]:
        """Get a JSON completion from the LLM.

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            temperature: Sampling temperature
            max_tokens: Maximum tokens in response

        Returns:
            Parsed JSON response
        """
        import json

        self._ensure_client()

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            response = await self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )

            content = response.choices[0].message.content or "{}"
            return json.loads(content)

        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON response", error=str(e))
            return {"error": "Failed to parse response", "raw": content}
        except Exception as e:
            logger.error("LLM completion failed", error=str(e))
            raise


def create_client(
    api_key: str | None = None,
    base_url: str = "https://api.openai.com/v1",
    model: str = "gpt-4o-mini",
    timeout: int = 30,
) -> LLMClient:
    """Create an LLM client.

    Args:
        api_key: OpenAI API key
        base_url: API base URL
        model: Model to use
        timeout: Request timeout

    Returns:
        Configured LLMClient instance
    """
    return LLMClient(
        api_key=api_key,
        base_url=base_url,
        model=model,
        timeout=timeout,
    )
