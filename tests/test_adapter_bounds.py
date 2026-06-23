"""Real-LLM bounding tests (AITW_TARGET_HARDENING_FIX2 P1.8).

Covers error classification, bounded retry vs fail-fast, the harness mapping AdapterError to a
specific end-telemetry outcome, and the loop's wall-clock timeout.
"""

import json

import pytest

from aitw.agent.adapters import anthropic_adapter as aa
from aitw.agent.adapters.anthropic_adapter import AnthropicAdapter, classify_adapter_error
from aitw.agent.adapters.base import AdapterError, Message
from aitw.agent.loop import AgentLoop
from aitw.orchestrator.run_harness import run
from test_run_harness import _records_from, make_scenario


# --- classification ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("APITimeoutError", "adapter_timeout"),
        ("RateLimitError", "adapter_rate_limited"),
        ("AuthenticationError", "adapter_auth_error"),
        ("PermissionDeniedError", "adapter_auth_error"),
        ("BadRequestError", "adapter_config_error"),
        ("NotFoundError", "adapter_config_error"),
        ("APIConnectionError", "adapter_provider_error"),
        ("SomethingWeird", "adapter_provider_error"),
    ],
)
def test_classify_by_name(name, expected):
    exc = type(name, (Exception,), {})()
    assert classify_adapter_error(exc) == expected


@pytest.mark.parametrize("status,expected", [(429, "adapter_rate_limited"), (401, "adapter_auth_error"), (400, "adapter_config_error")])
def test_classify_by_status_code(status, expected):
    exc = Exception("x")
    exc.status_code = status
    assert classify_adapter_error(exc) == expected


# --- retry vs fail-fast (fake client; sleep patched out) ---------------------------------------


class _Resp:
    def __init__(self, text):
        self.content = [type("B", (), {"type": "text", "text": text})()]


class _Messages:
    def __init__(self, fail_times, exc_factory):
        self.calls = 0
        self.fail_times = fail_times
        self.exc_factory = exc_factory

    def create(self, **kw):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.exc_factory()
        return _Resp("ok")


class _Client:
    def __init__(self, messages):
        self.messages = messages


def _adapter_with(messages, **kw):
    a = AnthropicAdapter(**kw)
    a._client = _Client(messages)  # bypass _ensure_client (no key/network)
    return a


def test_retryable_error_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(aa.time, "sleep", lambda *_: None)
    msgs = _Messages(fail_times=2, exc_factory=lambda: type("RateLimitError", (Exception,), {})())
    adapter = _adapter_with(msgs, max_retries=2)
    out = adapter.complete("sys", [Message("user", "hi")])
    assert out == "ok"
    assert msgs.calls == 3  # 2 failures + 1 success


def test_retry_is_bounded(monkeypatch):
    monkeypatch.setattr(aa.time, "sleep", lambda *_: None)
    msgs = _Messages(fail_times=99, exc_factory=lambda: type("RateLimitError", (Exception,), {})())
    adapter = _adapter_with(msgs, max_retries=2)
    with pytest.raises(AdapterError) as exc:
        adapter.complete("sys", [Message("user", "hi")])
    assert exc.value.classification == "adapter_rate_limited"
    assert msgs.calls == 3  # initial + 2 retries, then give up


def test_auth_error_is_not_retried(monkeypatch):
    monkeypatch.setattr(aa.time, "sleep", lambda *_: None)
    msgs = _Messages(fail_times=99, exc_factory=lambda: type("AuthenticationError", (Exception,), {})())
    adapter = _adapter_with(msgs, max_retries=5)
    with pytest.raises(AdapterError) as exc:
        adapter.complete("sys", [Message("user", "hi")])
    assert exc.value.classification == "adapter_auth_error"
    assert msgs.calls == 1  # no retries on auth failure


# --- harness maps AdapterError to a specific outcome -------------------------------------------


def test_run_classifies_adapter_timeout(tmp_path, monkeypatch):
    import aitw.orchestrator.run_harness as rh

    class _Boom:
        def complete(self, system, messages):
            raise AdapterError("adapter_timeout", "slow")

    monkeypatch.setattr(rh, "_build_adapter", lambda mc, sc: _Boom())
    with pytest.raises(AdapterError):
        run(make_scenario(), attack_fixture=None, runs_dir=tmp_path, run_id="at1")
    end = [r for r in _records_from(tmp_path / "at1.run.jsonl") if r.get("outcome") == "end"]
    assert end and end[0]["run_outcome"] == "adapter_timeout"


# --- loop wall-clock timeout -------------------------------------------------------------------


def test_loop_times_out(monkeypatch):
    import aitw.agent.loop as loop_mod

    ticks = iter([0.0, 100.0])
    monkeypatch.setattr(loop_mod.time, "monotonic", lambda: next(ticks))

    class _NeverCalled:
        def complete(self, system, messages):  # pragma: no cover - must not be reached
            raise AssertionError("adapter should not be called after timeout")

    loop = AgentLoop(_NeverCalled(), tools=None, max_steps=5, max_wall_clock_s=5.0)
    result = loop.run("sys", "task")
    assert result.outcome == "timeout"
