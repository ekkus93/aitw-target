"""Append-only JSONL telemetry log.

Plaintext, append-only, no crypto: it stays clear of any audit/receipt architecture and stays
legible. It is per-step telemetry, nothing more.

Every record carries the tag set so per-run telemetry can be computed:
    {tenant, scenario, step_no, tool, outcome, phase}
plus free-form fields (thought, args, result, action, final, ...).

Phases:
    "task"   — normal scenario execution steps
    "attack" — attack-fixture injection events applied by the harness
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from aitw.safety.limits import (
    MAX_TELEMETRY_EVENT_BYTES,
    MAX_TELEMETRY_STRING_BYTES,
    truncate_text,
)

REQUIRED_TAGS = ("tenant", "scenario", "step_no", "tool", "outcome", "phase")

# Credential-shaped values that must never be persisted to telemetry (FIX2 P1.7). These match
# secret VALUES, not env-var names, so a reference like "ANTHROPIC_API_KEY" (the name) is kept
# while an actual key value is scrubbed.
_REDACT_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_-]{10,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
]
_REDACTION = "[REDACTED-SECRET]"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(text: str) -> str:
    # Scrub the live provider key value explicitly (belt-and-suspenders), then known key shapes.
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key and key in text:
        text = text.replace(key, _REDACTION)
    for rx in _REDACT_PATTERNS:
        text = rx.sub(_REDACTION, text)
    return text


def _sanitize(value):
    """Recursively redact secrets and cap oversized strings in a telemetry value (FIX2 P1.7)."""
    if isinstance(value, str):
        red = _redact(value)
        capped, marker = truncate_text(red, MAX_TELEMETRY_STRING_BYTES)
        if marker:
            return f"{capped}…[truncated {marker['original_bytes']}B sha={marker['sha256_16']}]"
        return capped
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value


class ObservationLog:
    def __init__(self, path: str | Path, *, create_new: bool = False):
        """Open a telemetry log for WRITING.

        create_new=True opens with exclusive-create ("x") semantics so a run log can never be
        reopened in append mode over a prior run's records (run-id reuse must fail loudly — see
        FIX2 P0.3). The default append mode is for tests that write then re-read.

        To READ an existing log without ever creating one, use ObservationLog.read_existing()
        (FIX2 P1.2): the writer constructor creates the parent dir and a file handle, which is
        wrong for a pure read.
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("x" if create_new else "a", encoding="utf-8")
        # Safe-by-default telemetry: redact secrets and cap field/event sizes. The full-payload
        # escape hatch (FIX2 P1.7 / §9.4) is opt-in for local debugging only.
        self.safe = os.environ.get("AITW_UNSAFE_FULL_TELEMETRY") != "1"

    @classmethod
    def read_existing(cls, path: str | Path) -> "ObservationLog":
        """Return a READER bound to an existing log. Never creates a file.

        Raises FileNotFoundError if the log does not exist — a missing log is an error to surface,
        not an empty file to silently materialize (FIX2 P1.2). The returned object has no open
        write handle; calling an emit_* method on it raises.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"telemetry log not found: {p}")
        reader = cls.__new__(cls)
        reader.path = p
        reader._fh = None
        return reader

    # --- emit helpers --------------------------------------------------------

    def emit_step(self, *, tenant, scenario, phase, step) -> None:
        """Log one agent loop Step (see aitw.agent.loop.Step)."""
        self._write(
            {
                "tenant": tenant,
                "scenario": scenario,
                "phase": phase,
                "step_no": step.step_no,
                "tool": step.tool,
                "outcome": step.outcome,
                "thought": step.thought,
                "args": step.args,
                "result": step.result,
                "final": step.final,
            }
        )

    def emit_event(self, *, tenant, scenario, phase, step_no, outcome, tool=None, **fields) -> None:
        """Log a non-step event (attack injection, run boundary)."""
        record = {
            "tenant": tenant,
            "scenario": scenario,
            "phase": phase,
            "step_no": step_no,
            "tool": tool,
            "outcome": outcome,
        }
        record.update(fields)
        self._write(record)

    # --- io ------------------------------------------------------------------

    def _write(self, record: dict) -> None:
        if self._fh is None:
            raise RuntimeError("this ObservationLog is read-only (opened via read_existing)")
        missing = [tag for tag in REQUIRED_TAGS if tag not in record]
        if missing:
            raise ValueError(f"telemetry record missing required tags: {missing}")
        record.setdefault("ts", _now())
        if self.safe:
            record = self._make_safe(record)
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()

    def _make_safe(self, record: dict) -> dict:
        """Redact secrets, cap string fields, and bound the whole serialized event (FIX2 P1.7).

        Required tags are always preserved. If the event still exceeds the size cap after field
        capping, non-tag fields are dropped and replaced with a marker rather than writing an
        unbounded line.
        """
        safe = {k: (v if k in REQUIRED_TAGS else _sanitize(v)) for k, v in record.items()}
        # Tags themselves may be strings carrying secrets in pathological cases; redact in place
        # without size-capping (they are short and structurally required).
        for tag in REQUIRED_TAGS:
            if isinstance(safe.get(tag), str):
                safe[tag] = _redact(safe[tag])
        serialized = json.dumps(safe, default=str)
        if len(serialized.encode("utf-8")) <= MAX_TELEMETRY_EVENT_BYTES:
            return safe
        kept = {k: safe[k] for k in REQUIRED_TAGS if k in safe}
        kept["ts"] = safe.get("ts", _now())
        marker = truncate_text(serialized, MAX_TELEMETRY_EVENT_BYTES)[1]
        kept["_event_truncated"] = marker
        return kept

    def records(self) -> list[dict]:
        """Parse the JSONL log into records — strict, with ONE tolerance.

        A torn/partial FINAL line (e.g. a crash mid-write) is skipped, so the complete records
        before it survive. Any malformed NON-final line is corruption that must NOT be silently
        dropped — it raises, identifying the physical file line and path. Blank lines (including
        trailing ones) are ignored and do not count when deciding which line is "final".
        """
        with self.path.open("r", encoding="utf-8") as fh:
            raw = fh.readlines()
        # (physical 1-based line number, text) for non-blank lines only.
        nonblank = [(i, line) for i, line in enumerate(raw, start=1) if line.strip()]
        out: list[dict] = []
        for pos, (lineno, line) in enumerate(nonblank):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                if pos == len(nonblank) - 1:
                    continue  # tolerate a torn trailing line
                raise ValueError(
                    f"malformed telemetry record at {self.path}:{lineno} (not valid JSON)"
                ) from exc
        return out

    def close(self) -> None:
        if self._fh is not None and not self._fh.closed:
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
