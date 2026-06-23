"""Minimal hand-rolled ReAct loop: plan -> act -> observe, until a final answer or step cap.

Deliberately ~1 file, no framework. The model returns one JSON action per turn; the loop
parses it, calls a tool, feeds the observation back, and repeats. An `on_step` callback lets
the orchestrator log every step (the observation log is wired in the run harness).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Protocol

from aitw.agent.adapters.base import Message, ModelAdapter


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
    outcome: str = "no_steps"  # "final" | "max_steps" | "parse_error"


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
    def __init__(self, adapter: ModelAdapter, tools: ToolCaller, max_steps: int = 8):
        self.adapter = adapter
        self.tools = tools
        self.max_steps = max_steps

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
        for step_no in range(1, self.max_steps + 1):
            raw = self.adapter.complete(system, messages)
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
            except Exception as exc:  # tools surface failures as observations, not crashes
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
