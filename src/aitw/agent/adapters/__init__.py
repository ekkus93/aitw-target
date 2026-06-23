"""Model adapters. Boring, model-agnostic interface (base) + Anthropic + deterministic mock."""

from aitw.agent.adapters.base import Message, ModelAdapter
from aitw.agent.adapters.mock_adapter import MockAdapter

__all__ = ["Message", "ModelAdapter", "MockAdapter"]
