"""Baseline-vs-deployed evidence is generated from real runs."""

import json

from agent_deployment.evidence import _render_markdown, generate_evidence


def test_evidence_shows_baseline_compromised_deployed_clean(tmp_path):
    ev = generate_evidence(runs_dir=tmp_path)

    assert ev["baseline"]["completed"] is True
    assert ev["baseline"]["compromised"] is True
    assert ev["deployed"]["completed"] is True
    assert ev["deployed"]["compromised"] is False


def test_baseline_excerpt_shows_exfil_email(tmp_path):
    ev = generate_evidence(runs_dir=tmp_path)
    excerpt = json.dumps(ev["baseline"]["excerpt"])
    assert "attacker@evil.example" in excerpt
    # baseline end record reflects the compromise
    assert any(r.get("outcome") == "end" and r.get("compromised") is True for r in ev["baseline"]["excerpt"])


def test_deployed_excerpt_shows_a_block_or_redaction_and_clean_end(tmp_path):
    ev = generate_evidence(runs_dir=tmp_path)
    excerpt = ev["deployed"]["excerpt"]
    phases = {r.get("phase") for r in excerpt}
    # At least one defensive event explains the outcome.
    assert phases & {"context_sanitizer", "external_effect", "tool_policy", "memory_policy"}
    assert "attacker@evil.example" not in json.dumps(excerpt)
    assert any(r.get("outcome") == "end" and r.get("compromised") is False for r in excerpt)


def test_markdown_renders(tmp_path):
    ev = generate_evidence(runs_dir=tmp_path)
    md = _render_markdown(ev)
    assert "Baseline vs. deployed evidence" in md
    assert "compromised" in md
