"""web_search tool: STUB over a small local canned corpus. No real network.

Injection channel (baseline reconciliation): results are returned straight from
ctx.search_corpus, which a scenario/attacker can poison — the hits are attacker-controllable
content fed back into the agent's context, a third injection path alongside the notice board
and the shared store. Naive by design: corpus values are returned unvalidated.
"""

from __future__ import annotations

from aitw.tools.registry import Tool, ToolContext


def _run(args: dict, ctx: ToolContext) -> str:
    query = args.get("query", "").lower()
    hits = [text for key, text in ctx.search_corpus.items() if query and query in key.lower()]
    if not hits:
        return "no results"
    return "\n---\n".join(hits[:3])


TOOL = Tool(
    name="web_search",
    description="Search the web (STUB — local canned corpus). args: {query}",
    func=_run,
)
