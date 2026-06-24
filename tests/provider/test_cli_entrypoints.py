"""CLI entrypoint coverage for the dev/build tools: run_local, evidence, round2_packaging,
packaging, and round2_artifact_scan ``main()`` functions (happy paths + error/branch exits).

These are dev-only tools (not shipped in the artifact), but their main() boundaries should still be
exercised so an error path can't silently regress.
"""

from agent_deployment import evidence, packaging, round2_artifact_scan, round2_packaging, run_local


# --- run_local.main ----------------------------------------------------------------------------


def test_run_local_main_happy(tmp_path, capsys):
    rc = run_local.main(
        ["--scenario", "support_triage", "--runs-dir", str(tmp_path / "runs"), "--run-id", "cli-ok"]
    )
    assert rc == 0
    assert '"completed"' in capsys.readouterr().out  # report JSON printed


def test_run_local_main_bad_run_id_returns_2(tmp_path, capsys):
    # An invalid run-id is rejected by the harness (ValueError) -> exit 2.
    rc = run_local.main(
        ["--scenario", "support_triage", "--runs-dir", str(tmp_path / "runs"), "--run-id", "bad/id"]
    )
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_run_local_main_bad_fixture_returns_2(tmp_path, capsys):
    # A missing fixture path is a CliError -> exit 2.
    rc = run_local.main(
        [
            "--scenario", "support_triage",
            "--runs-dir", str(tmp_path / "runs"),
            "--fixture", str(tmp_path / "nope.yaml"),
        ]
    )
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_run_local_main_inrun_failure_returns_1(tmp_path, capsys, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("in-run boom")

    monkeypatch.setattr(run_local, "run_with_deployment", _boom)
    rc = run_local.main(["--scenario", "support_triage", "--runs-dir", str(tmp_path / "runs")])
    assert rc == 1
    assert "run failed" in capsys.readouterr().err


# --- evidence.main -----------------------------------------------------------------------------


def test_evidence_main_writes_files(tmp_path, capsys):
    out = tmp_path / "evidence_out"
    rc = evidence.main(["--out", str(out), "--runs-dir", str(tmp_path / "runs")])
    assert rc == 0
    assert (out / "evidence.json").is_file()
    assert (out / "evidence.md").is_file()
    assert "evidence written to" in capsys.readouterr().out


def test_evidence_main_stdout_only(tmp_path, capsys):
    rc = evidence.main(["--runs-dir", str(tmp_path / "runs")])
    assert rc == 0
    assert '"baseline"' in capsys.readouterr().out


def test_evidence_main_failure_returns_1(tmp_path, capsys, monkeypatch):
    def _boom(**k):
        raise RuntimeError("evidence boom")

    monkeypatch.setattr(evidence, "generate_evidence", _boom)
    rc = evidence.main(["--runs-dir", str(tmp_path / "runs")])
    assert rc == 1
    assert "evidence generation failed" in capsys.readouterr().err


# --- round2_packaging.main ---------------------------------------------------------------------


def test_round2_packaging_main_verified(tmp_path, capsys):
    rc = round2_packaging.main(["--out", str(tmp_path / "art")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "round2 artifact built" in out
    assert "host-layout import check: verified" in out


def test_round2_packaging_main_import_check_disabled(tmp_path, capsys):
    rc = round2_packaging.main(["--out", str(tmp_path / "art"), "--no-import-check"])
    assert rc == 0
    assert "host-layout import check: skipped (--no-import-check)" in capsys.readouterr().out


def test_round2_packaging_main_skips_without_host(tmp_path, capsys):
    rc = round2_packaging.main(
        ["--out", str(tmp_path / "art"), "--host-src", str(tmp_path / "no-host")]
    )
    assert rc == 0
    assert "NOT verified" in capsys.readouterr().out


def test_round2_packaging_main_scan_failure_returns_1(tmp_path, capsys, monkeypatch):
    fake = [round2_artifact_scan.ScanFinding("x.py", "label", "blue team")]
    monkeypatch.setattr(round2_packaging, "scan_round2_artifact", lambda root: fake)
    rc = round2_packaging.main(["--out", str(tmp_path / "art")])
    assert rc == 1
    assert "export failed" in capsys.readouterr().err


# --- round2_artifact_scan.main -----------------------------------------------------------------


def test_round2_scan_main_clean(tmp_path, capsys):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    rc = round2_artifact_scan.main(["--path", str(out)])
    assert rc == 0
    assert "clean" in capsys.readouterr().out


def test_round2_scan_main_dirty(tmp_path, capsys):
    out = round2_packaging.build_round2_artifact(tmp_path / "art")
    (out / "src" / "agent_deployment" / "x.py").write_text("# blue team\n", encoding="utf-8")
    rc = round2_artifact_scan.main(["--path", str(out)])
    assert rc == 1
    assert "issue(s)" in capsys.readouterr().err


# --- packaging.main (legacy exporter) ----------------------------------------------------------


def test_packaging_main_happy(tmp_path, capsys):
    rc = packaging.main(["--out", str(tmp_path / "legacy")])
    assert rc == 0
    assert "artifact built" in capsys.readouterr().out


def test_packaging_main_rebuild_over_existing(tmp_path, capsys):
    # Building twice exercises the replace-if-exists path.
    assert packaging.main(["--out", str(tmp_path / "legacy")]) == 0
    assert packaging.main(["--out", str(tmp_path / "legacy")]) == 0


def test_packaging_main_zip(tmp_path, capsys):
    rc = packaging.main(["--out", str(tmp_path / "legacy"), "--zip"])
    assert rc == 0
    assert "archive:" in capsys.readouterr().out
    assert (tmp_path / "legacy.zip").is_file()


def test_packaging_main_scan_failure_returns_1(tmp_path, capsys, monkeypatch):
    from agent_deployment.artifact_scan import ScanFinding

    fake = [ScanFinding("x.py", "label", "blue team")]
    monkeypatch.setattr(packaging, "scan_artifact", lambda root: fake)
    rc = packaging.main(["--out", str(tmp_path / "legacy")])
    assert rc == 1
    assert "export failed" in capsys.readouterr().err
