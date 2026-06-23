"""Real Anthropic model adapter (one working real config).

The API key is read from the environment (ANTHROPIC_API_KEY) — the one allowed real secret.
The `anthropic` package is imported lazily so that offline / mock runs and the test suite
never require the dependency or a key.
"""

from __future__ import annotations

import os

from aitw.agent.adapters.base import Message

# Default to the latest, most capable Claude model; override per tenant in config/tenants.yaml.
DEFAULT_MODEL = "claude-opus-4-8"


class AnthropicAdapter:
    def __init__(self, model: str = DEFAULT_MODEL, max_tokens: int = 1024, name: str | None = None):
        self.model = model
        self.max_tokens = max_tokens
        self.name = name or f"anthropic:{model}"
        self._client = None

    def _ensure_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "The 'anthropic' package is required for the real adapter. "
                    "Install it, or use the MockAdapter for offline runs."
                ) from exc
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY is not set. It is the one allowed real secret; "
                    "put it in .env (gitignored) or use the MockAdapter."
                )
            self._client = anthropic.Anthropic(api_key=key)
        return self._client

    def complete(self, system: str, messages: list[Message]) -> str:  # pragma: no cover - needs network/key
        client = self._ensure_client()
        api_messages = [{"role": _role(m.role), "content": m.content} for m in messages]
        resp = client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=api_messages,
        )
        return "".join(block.text for block in resp.content if getattr(block, "type", None) == "text")


def _role(role: str) -> str:
    # The Anthropic messages API only accepts 'user' / 'assistant'. Map tool observations to user.
    return "assistant" if role == "assistant" else "user"
