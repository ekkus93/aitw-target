"""Real Anthropic model adapter (one working real config).

The API key is read from the environment (ANTHROPIC_API_KEY) — the one allowed real secret.
The `anthropic` package is imported lazily so that offline / mock runs and the test suite
never require the dependency or a key.

Real runs are BOUNDED (FIX2 P1.8 / §12): each request has a timeout, transient provider/network
failures are retried a bounded number of times, and auth/validation failures are NOT retried.
Every provider failure is mapped to an AdapterError with a classification the harness records as a
specific end-telemetry outcome (adapter_timeout / adapter_rate_limited / adapter_auth_error /
adapter_provider_error / adapter_config_error).
"""

from __future__ import annotations

import os
import time

from aitw.agent.adapters.base import AdapterError, Message

# Default to the latest, most capable Claude model; override per tenant in config/tenants.yaml.
DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_TIMEOUT_S = 60.0
DEFAULT_MAX_RETRIES = 2

# Classifications that are transient and worth retrying; the rest fail fast.
_RETRYABLE = {"adapter_timeout", "adapter_rate_limited", "adapter_provider_error"}


def classify_adapter_error(exc: Exception) -> str:
    """Map a provider/network exception to an ADAPTER_OUTCOMES classification.

    Classifies by exception class name and any HTTP status code attribute, so it works without
    importing the anthropic SDK (keeping offline/test paths dependency-free).
    """
    name = type(exc).__name__.lower()
    status = getattr(exc, "status_code", None)

    if "timeout" in name:
        return "adapter_timeout"
    if "ratelimit" in name or status == 429:
        return "adapter_rate_limited"
    if "authentication" in name or "permission" in name or status in (401, 403):
        return "adapter_auth_error"
    if "badrequest" in name or "notfound" in name or "unprocessable" in name or status in (400, 404, 422):
        return "adapter_config_error"
    return "adapter_provider_error"


class AnthropicAdapter:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 1024,
        name: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        self.model = model
        self.max_tokens = max_tokens
        self.name = name or f"anthropic:{model}"
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self._client = None

    def _ensure_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover
                raise AdapterError(
                    "adapter_config_error",
                    "The 'anthropic' package is required for the real adapter. "
                    "Install it, or use the MockAdapter for offline runs.",
                ) from exc
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise AdapterError(
                    "adapter_auth_error",
                    "ANTHROPIC_API_KEY is not set. It is the one allowed real secret; "
                    "export it into your shell or use the MockAdapter.",
                )
            self._client = anthropic.Anthropic(api_key=key, timeout=self.timeout_s)
        return self._client

    def complete(self, system: str, messages: list[Message]) -> str:  # pragma: no cover - needs network/key
        client = self._ensure_client()
        api_messages = [{"role": _role(m.role), "content": m.content} for m in messages]
        attempt = 0
        while True:
            try:
                resp = client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=system,
                    messages=api_messages,
                )
                return "".join(
                    block.text for block in resp.content if getattr(block, "type", None) == "text"
                )
            except AdapterError:
                raise
            except Exception as exc:  # noqa: BLE001 — classify every provider/network failure
                classification = classify_adapter_error(exc)
                if classification in _RETRYABLE and attempt < self.max_retries:
                    attempt += 1
                    time.sleep(min(2**attempt, 8))  # simple bounded backoff
                    continue
                raise AdapterError(classification, str(exc)) from exc


def _role(role: str) -> str:
    # The Anthropic messages API only accepts 'user' / 'assistant'. Map tool observations to user.
    return "assistant" if role == "assistant" else "user"
