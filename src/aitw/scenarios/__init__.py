"""Scenario registry. The three mundane business jobs the agents perform.

Factories are imported lazily so importing `aitw.scenarios.base` (done by the run harness)
stays cheap and free of import-order concerns.
"""

from __future__ import annotations

from aitw.scenarios.base import RunArtifacts, Scenario

_NAMES = ("support_triage", "ops_summary", "research_assistant")


def scenario_names() -> list[str]:
    return list(_NAMES)


def get_scenario(name: str) -> Scenario:
    if name not in _NAMES:
        raise KeyError(f"unknown scenario: {name!r} (choices: {', '.join(_NAMES)})")
    from aitw.scenarios import ops_summary, research_assistant, support_triage

    factories = {
        "support_triage": support_triage.make,
        "ops_summary": ops_summary.make,
        "research_assistant": research_assistant.make,
    }
    return factories[name]()


__all__ = ["Scenario", "RunArtifacts", "scenario_names", "get_scenario"]
