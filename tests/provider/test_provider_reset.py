"""Provider reset command: guarded, fail-loud teardown of regenerable artifacts."""

from agent_deployment.reset import main, reset_targets


def test_removes_allowlisted_dirs_under_root(tmp_path):
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "x.run.jsonl").write_text("{}", encoding="utf-8")
    (tmp_path / "workspaces").mkdir()
    result = reset_targets(("runs", "workspaces"), root=tmp_path)
    assert result.ok
    assert len(result.removed) == 2
    assert not (tmp_path / "runs").exists()
    assert not (tmp_path / "workspaces").exists()


def test_nothing_to_remove_is_ok(tmp_path):
    result = reset_targets(("runs", "workspaces"), root=tmp_path)
    assert result.ok
    assert result.removed == []


def test_refuses_non_allowlisted_basename(tmp_path):
    (tmp_path / "src").mkdir()
    result = reset_targets(("src",), root=tmp_path)
    assert not result.ok
    assert result.refused
    assert (tmp_path / "src").exists()       # untouched


def test_refuses_target_outside_root(tmp_path):
    outside = tmp_path.parent / "runs"
    result = reset_targets((str(outside),), root=tmp_path)
    assert not result.ok
    assert result.refused


def test_cli_exit_zero_on_clean(tmp_path):
    assert main(["--root", str(tmp_path)]) == 0


def test_cli_exit_nonzero_on_refusal(tmp_path):
    (tmp_path / "secrets").mkdir()
    assert main(["secrets", "--root", str(tmp_path)]) == 1
