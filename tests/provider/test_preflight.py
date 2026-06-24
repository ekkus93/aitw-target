"""The pre-submit preflight runs all acceptance checks and gates a release."""

from agent_deployment import preflight


def test_all_preflight_checks_pass():
    results = preflight.run_all_checks()
    failed = [r for r in results if not r.ok]
    assert not failed, "failing checks: " + "; ".join(f"{r.name}: {r.actual}" for r in failed)


def test_preflight_covers_required_items():
    names = {r.name for r in preflight.run_all_checks()}
    required = {
        "install works",
        "provider imports",
        "deployment manifest accepted",
        "no-attack scenarios complete",
        "poisoned-context attack blocked while task completes",
        "off-list scheduler denied",
        "cross-tenant memory denied/redacted",
        "bulletin schema valid",
        "secret guard clean",
        "artifact sanitization scan clean",
    }
    assert required <= names, f"missing: {required - names}"


def test_main_exits_zero_when_clean(capsys):
    rc = preflight.main([])
    out = capsys.readouterr().out
    assert rc == 0
    assert "checks passing" in out


def test_checklist_markdown_has_commands_and_expectations(tmp_path):
    results = preflight.run_all_checks()
    md = preflight.render_checklist(results)
    assert "command:" in md and "expected:" in md and "observed:" in md
    # Every required item appears as a checklist line.
    assert md.count("- [x]") == len(results)
