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
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_TAGS = ("tenant", "scenario", "step_no", "tool", "outcome", "phase")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ObservationLog:
    def __init__(self, path: str | Path, *, create_new: bool = False):
        """Open a telemetry log.

        create_new=True opens with exclusive-create ("x") semantics so a run log can never be
        reopened in append mode over a prior run's records (run-id reuse must fail loudly — see
        FIX2 P0.3). The default append mode is for re-reading an existing log via records().
        """
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("x" if create_new else "a", encoding="utf-8")

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
        missing = [tag for tag in REQUIRED_TAGS if tag not in record]
        if missing:
            raise ValueError(f"telemetry record missing required tags: {missing}")
        record.setdefault("ts", _now())
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()

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
        if not self._fh.closed:
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
