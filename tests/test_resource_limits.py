"""Resource-limit tests (AITW_TARGET_HARDENING_FIX2 P1.6).

Caps bound a single run's artifacts/payloads without changing the naive target behavior. Every
cap that fires is recorded so a capped run is never mistaken for a clean one.
"""

import dataclasses
import json

import pytest

from aitw.context.store import ContextStore
from aitw.orchestrator.run_harness import run
from aitw.safety import limits
from aitw.safety.limits import truncate_text
from aitw.tools import file_io, shared_memory
from aitw.tools.registry import Tool, ToolContext, ToolRegistry
from test_run_harness import _records_from, make_scenario


def _ctx(tmp_path, **kw):
    return ToolContext(tenant_id="t", workspace=tmp_path, **kw)


# --- truncate_text helper ----------------------------------------------------------------------


def test_truncate_text_marks_when_over_cap():
    text, marker = truncate_text("abcdef", 3)
    assert text == "abc"
    assert marker and marker["original_bytes"] == 6 and marker["truncated"] is True


def test_truncate_text_noop_under_cap():
    text, marker = truncate_text("ab", 10)
    assert text == "ab" and marker is None


# --- file_io write caps ------------------------------------------------------------------------


def test_oversized_single_file_write_fails(tmp_path):
    ctx = _ctx(tmp_path)
    big = "A" * (limits.MAX_FILE_WRITE_BYTES + 1)
    with pytest.raises(ValueError):
        file_io._run({"op": "write", "path": "f.txt", "content": big}, ctx)
    assert any(t["kind"] == "file_write_rejected" for t in ctx.truncations)
    assert ctx.file_writes == []  # nothing recorded as written


def test_per_run_file_write_budget_enforced(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    monkeypatch.setattr(limits, "MAX_TOTAL_FILE_WRITES_BYTES", 10)
    monkeypatch.setattr(file_io, "MAX_TOTAL_FILE_WRITES_BYTES", 10)
    file_io._run({"op": "write", "path": "a.txt", "content": "12345"}, ctx)  # ok (5)
    with pytest.raises(ValueError):
        file_io._run({"op": "write", "path": "b.txt", "content": "67890123"}, ctx)  # would exceed
    assert any(t["kind"] == "file_write_budget_exceeded" for t in ctx.truncations)


# --- shared_memory value cap -------------------------------------------------------------------


def test_shared_memory_value_truncated(tmp_path):
    store = ContextStore(":memory:")
    ctx = _ctx(tmp_path, store=store)
    big = "Z" * (limits.MAX_SHARED_MEMORY_VALUE_BYTES + 100)
    shared_memory._run({"op": "write", "name": "n", "content": big}, ctx)
    stored = store.get_value("t", "memory", "n")
    assert len(stored.encode("utf-8")) <= limits.MAX_SHARED_MEMORY_VALUE_BYTES
    assert any(t["kind"] == "shared_memory_value" for t in ctx.truncations)


# --- tool-result cap (applied in the registry) -------------------------------------------------


def test_tool_result_truncated_in_registry(tmp_path):
    ctx = _ctx(tmp_path)
    reg = ToolRegistry(ctx)
    big = "Q" * (limits.MAX_TOOL_RESULT_BYTES + 50)
    reg.register(Tool("huge", "d", lambda a, c: big))
    out = reg.call("huge", {})
    assert len(out.encode("utf-8")) <= limits.MAX_TOOL_RESULT_BYTES
    assert any(t["kind"] == "tool_result" for t in ctx.truncations)


# --- end-to-end: truncation count surfaces in report + telemetry -------------------------------


def test_resource_truncation_count_surfaced(tmp_path):
    big = "Z" * (limits.MAX_SHARED_MEMORY_VALUE_BYTES + 10)
    sc = dataclasses.replace(
        make_scenario(),
        susceptible=False,
        mock_script=[
            json.dumps({"thought": "store", "tool": "shared_memory", "args": {"op": "write", "content": big}}),
            json.dumps(
                {"thought": "reply", "tool": "send_email",
                 "args": {"to": "customer@acme.test", "subject": "Re", "body": "On it."}}
            ),
            json.dumps({"thought": "done", "final": "ok"}),
        ],
    )
    report = run(sc, attack_fixture=None, runs_dir=tmp_path, run_id="rt1")
    assert report.resource_truncation_count >= 1
    end = [r for r in _records_from(tmp_path / "rt1.run.jsonl") if r.get("outcome") == "end"]
    assert end and end[0]["resource_truncation_count"] >= 1
