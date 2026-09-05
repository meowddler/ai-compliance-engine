"""AI provider abstraction.

The application never talks to a model vendor directly. It goes through this
interface, so the provider can be swapped (NVIDIA today, another tomorrow)
without touching any calling code.

THE TRUST BOUNDARY — enforced by design, not convention:
    AI proposes and explains. Deterministic rules decide.

Nothing returned from a provider may set a compliance status. Every response
is a proposal that either the deterministic engine confirms or a human
approves. Providers return text and metadata; they never return a verdict the
system acts on unreviewed.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class AIResponse:
    """A single model response plus everything needed to audit it later."""
    text: str
    model: str
    provider: str
    prompt_version: str
    latency_ms: int
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    error: Optional[str] = None
    raw: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


class AIProvider(ABC):
    """Interface every provider implements."""

    name: str = "base"

    @abstractmethod
    def complete(self, system_prompt: str, user_content: str,
                 prompt_version: str, max_tokens: int = 1024,
                 temperature: float = 0.2) -> AIResponse:
        """Send one request and return a response with audit metadata."""
        raise NotImplementedError

    @abstractmethod
    def is_configured(self) -> bool:
        """True if this provider has what it needs to make real calls."""
        raise NotImplementedError


class NvidiaProvider(AIProvider):
    """NVIDIA NIM endpoint — OpenAI-compatible API surface."""

    name = "nvidia"

    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self._client = None

    def is_configured(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)

    def _get_client(self):
        if self._client is None:
            from openai import OpenAI          # imported lazily so the app runs without the lib
            self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)
        return self._client

    def complete(self, system_prompt, user_content, prompt_version,
                 max_tokens=1024, temperature=0.2) -> AIResponse:
        started = time.time()

        if not self.is_configured():
            return AIResponse(
                text="", model=self.model, provider=self.name,
                prompt_version=prompt_version, latency_ms=0,
                error="Provider not configured (missing API key, base URL, or model).",
            )

        try:
            client = self._get_client()
            completion = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    # Untrusted content is kept in the USER turn, never merged
                    # into the system prompt. This is the prompt-injection
                    # boundary: instructions and data stay separated.
                    {"role": "user", "content": user_content},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
                stream=False,
            )
            text = (completion.choices[0].message.content or "").strip()
            usage = getattr(completion, "usage", None)
            return AIResponse(
                text=text,
                model=self.model,
                provider=self.name,
                prompt_version=prompt_version,
                latency_ms=int((time.time() - started) * 1000),
                prompt_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
                completion_tokens=getattr(usage, "completion_tokens", None) if usage else None,
                raw=text,
            )
        except Exception as exc:
            return AIResponse(
                text="", model=self.model, provider=self.name,
                prompt_version=prompt_version,
                latency_ms=int((time.time() - started) * 1000),
                error=f"{type(exc).__name__}: {exc}",
            )


class StubProvider(AIProvider):
    """Development provider. Returns a clearly-labelled placeholder.

    This exists so the pipeline is runnable and testable without a live API.
    It never pretends to be a real model — every response is explicitly marked
    as a stub so it can't be mistaken for genuine model output.
    """

    name = "stub"

    def is_configured(self) -> bool:
        return True

    def complete(self, system_prompt, user_content, prompt_version,
                 max_tokens=1024, temperature=0.2) -> AIResponse:
        return AIResponse(
            text="[STUB PROVIDER — no live model configured. This is placeholder "
                 "output for development and must not be treated as analysis.]",
            model="stub", provider=self.name, prompt_version=prompt_version,
            latency_ms=0,
        )


def get_provider(provider_name: str, api_key: str = "", base_url: str = "", model: str = "") -> AIProvider:
    """Factory: pick a provider by name, falling back to the stub."""
    if provider_name == "nvidia":
        p = NvidiaProvider(api_key=api_key, base_url=base_url, model=model)
        return p if p.is_configured() else StubProvider()
    return StubProvider()