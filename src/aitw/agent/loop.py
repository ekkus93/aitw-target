"""Minimal hand-rolled ReAct loop: plan -> act -> observe, until a final answer or step cap.

Deliberately ~1 file, no framework. The model returns one JSON action per turn; the loop
parses it, calls a tool, feeds the observation back, and repeats. An `on_step` callback lets
the orchestrator log every step (the observation log is wired in the run harness).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

from aitw.agent.adapters.base import Message, ModelAdapter
from aitw.safety.limits import MAX_MODEL_RESPONSE_BYTES, truncate_text


class ToolCaller(Protocol):
    def call(self, name: str, args: dict) -> str: ...


@dataclass
class Action:
    thought: str = ""
    tool: str | None = None
    args: dict | None = None
    final: str | None = None


@dataclass
class Step:
    step_no: int
    thought: str
    tool: str | None
    args: dict
    result: str | None
    outcome: str  # "ok" | "tool_error" | "final" | "parse_error"
    final: str | None = None


@dataclass
class RunResult:
    steps: list[Step] = field(default_factory=list)
    final: str | None = None
    outcome: str = "no_steps"  # "final" | "max_steps" | "parse_error" | "timeout"
    truncation_count: int = 0  # model responses truncated by the resource cap (FIX2 P1.6)


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def parse_action(raw: str) -> Action:
    data = _extract_json(raw)
    if data is None:
        return Action()
    return Action(
        thought=str(data.get("thought", "")),
        tool=data.get("tool"),
        args=data.get("args") or {},
        final=data.get("final"),
    )


class AgentLoop:
    def __init__(
        self,
        adapter: ModelAdapter,
        tools: ToolCaller,
        max_steps: int = 8,
        max_wall_clock_s: float | None = None,
    ):
        self.adapter = adapter
        self.tools = tools
        self.max_steps = max_steps
        # Wall-clock bound for the whole loop (FIX2 P1.8). None disables it (the deterministic
        # mock has no reason to time out); real-model runs pass a budget from config.
        self.max_wall_clock_s = max_wall_clock_s

    def run(
        self,
        system: str,
        task: str,
        context_blob: str = "",
        on_step: Callable[[Step], None] | None = None,
    ) -> RunResult:
        messages: list[Message] = [Message("user", task)]
        if context_blob:
            messages.append(Message("user", f"Context available to you:\n{context_blob}"))

        result = RunResult()
        deadline = (
            time.monotonic() + self.max_wall_clock_s if self.max_wall_clock_s else None
        )
        for step_no in range(1, self.max_steps + 1):
            if deadline is not None and time.monotonic() > deadline:
                result.outcome = "timeout"
                return result
            raw = self.adapter.complete(system, messages)
            raw, marker = truncate_text(raw, MAX_MODEL_RESPONSE_BYTES)
            if marker:
                result.truncation_count += 1
            action = parse_action(raw)

            if action.tool is None and action.final is None:
                step = Step(step_no, action.thought, None, {}, raw[:200], "parse_error")
                _record(result, step, on_step)
                result.outcome = "parse_error"
                return result

            if action.final is not None:
                step = Step(step_no, action.thought, None, {}, None, "final", action.final)
                _record(result, step, on_step)
                result.final = action.final
                result.outcome = "final"
                return result

            try:
                tool_result = self.tools.call(action.tool, action.args or {})
                outcome = "ok"
            except (LookupError, OSError, ValueError, TypeError, RuntimeError, ArithmeticError) as exc:
                # A tool surfaces a failure as an observation, not a crash. This explicit set covers
                # the tool layer's raises (unknown tool -> KeyError; file_io -> ValueError; plus IO /
                # type / arithmetic faults); a genuinely unexpected error type still propagates.
                tool_result = f"ERROR: {exc}"
                outcome = "tool_error"
            step = Step(step_no, action.thought, action.tool, action.args or {}, tool_result, outcome)
            _record(result, step, on_step)

            messages.append(Message("assistant", raw))
            messages.append(Message("tool", f"[{action.tool}] -> {tool_result}"))

        result.outcome = "max_steps"
        return result


def _record(result: RunResult, step: Step, on_step) -> None:
    result.steps.append(step)
    if on_step is not None:
        on_step(step)
