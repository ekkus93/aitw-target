"""Model-adapter interface.

A model adapter takes a system prompt plus a list of messages and returns the model's raw
text response. The agent loop expects that text to contain a single JSON action object (see
aitw.agent.loop). Keeping the interface this thin is deliberate: the loop is model-agnostic
and every adapter (real or mock) is trivially substitutable per tenant config.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass
class Message:
    role: str  # "user" | "assistant" | "tool"
    content: str


@runtime_checkable
class ModelAdapter(Protocol):
    name: str

    def complete(self, system: str, messages: list[Message]) -> str:
        """Return the model's raw text response (expected to contain one JSON action)."""
        ...
