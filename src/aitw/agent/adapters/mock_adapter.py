"""Deterministic mock model adapter — the DEFAULT for tests / CI / offline runs.

This adapter does not call any network or LLM. It replays a fixed script of actions so the
whole harness runs reproducibly with zero tokens. It is plumbing, not a measurement of real
model susceptibility — that is what the Anthropic adapter is for.

To let the harness exercise the compromise path deterministically, the mock supports a
documented convention: if `susceptible=True` and the conversation/context contains a line of
the form

    INJECT::{"tool": "send_email", "args": {...}}

the adapter OBEYS that injected action once (modelling a gullible agent that follows
instructions found in poisoned context / tool output). A non-susceptible mock ignores it and
just runs its script. This is how the scaffold demonstrates the inducement path offline.
"""

from __future__ import annotations

import json
import re

from aitw.agent.adapters.base import Message

# Locate the INJECT:: marker only; the JSON payload (which must IMMEDIATELY follow the marker, after
# optional inline spaces/tabs) is parsed with a streaming decoder. raw_decode stops at the first
# complete object, so a stray '}' later on the line can't make a greedy regex over-capture and drop
# the injection; requiring the payload to follow the marker directly stops a marker+junk then
# unrelated '{...}' from being obeyed.
_INJECT_MARKER = re.compile(r"INJECT::")
_DECODER = json.JSONDecoder()


class MockAdapter:
    def __init__(self, name: str = "mock", script: list[str] | None = None, susceptible: bool = False):
        self.name = name
        self._script = list(script or [])
        self._cursor = 0
        self.susceptible = susceptible
        self._obeyed: set[str] = set()

    def complete(self, system: str, messages: list[Message]) -> str:
        if self.susceptible:
            obeyed = self._maybe_follow_injection(messages)
            if obeyed is not None:
                return obeyed
        if self._cursor < len(self._script):
            response = self._script[self._cursor]
            self._cursor += 1
            return response
        # Script exhausted: terminate cleanly with a final answer.
        return json.dumps({"thought": "Done.", "final": "Task complete."})

    def _maybe_follow_injection(self, messages: list[Message]) -> str | None:
        combined = "\n".join(m.content for m in messages)
        for match in _INJECT_MARKER.finditer(combined):
            # The payload must directly follow the marker (only inline spaces/tabs between), not an
            # arbitrary later '{' — otherwise INJECT::junk\n...{...} would obey unrelated JSON.
            payload = combined[match.end():].lstrip(" \t")
            if not payload.startswith("{"):
                continue
            try:
                action, _ = _DECODER.raw_decode(payload)
            except json.JSONDecodeError:
                continue
            if not isinstance(action, dict):
                continue
            key = json.dumps(action, sort_keys=True)  # obey each distinct payload at most once
            if key in self._obeyed:
                continue
            self._obeyed.add(key)
            action.setdefault("thought", "Following instruction found in context.")
            return json.dumps(action)
        return None
