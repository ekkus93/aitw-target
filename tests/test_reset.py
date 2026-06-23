"""reset() destructive-path guard (containment).

The basename-only SAFE_NAMES check let reset(("/anything/runs",)) rmtree an arbitrary absolute
path. The guard must additionally require the resolved target to live under the project root, so
the docstring's promise ("a mistyped path can't nuke the repo") actually holds.
"""

import aitw.safety.reset as reset_mod


def test_reset_refuses_dir_outside_project_root(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.setattr(reset_mod, "PROJECT_ROOT", root.resolve(), raising=False)

    # A directory whose basename IS allowed ("runs") but which lives OUTSIDE the project root.
    outside = tmp_path / "runs"
    outside.mkdir()
    (outside / "keep.txt").write_text("do not delete me", encoding="utf-8")

    removed = reset_mod.reset(targets=(str(outside),))

    assert removed == [], "a target outside the project root must be refused"
    assert outside.exists(), "the outside directory must NOT be deleted"


def test_reset_removes_allowed_dir_inside_project_root(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    monkeypatch.setattr(reset_mod, "PROJECT_ROOT", root, raising=False)

    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "x.run.jsonl").write_text("{}", encoding="utf-8")

    removed = reset_mod.reset(targets=(str(runs),))

    assert removed == [str(runs.resolve())]
    assert not runs.exists()


# --- exit codes: a refused/failed target must surface as non-zero (FIX2 P1.12) ----------------


def test_main_returns_nonzero_on_refused_target(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.setattr(reset_mod, "PROJECT_ROOT", root.resolve(), raising=False)
    outside = tmp_path / "runs"  # allowed basename, but outside the project root
    outside.mkdir()
    assert reset_mod.main([str(outside)]) == 1
    assert outside.exists(), "refused target must not be deleted"


def test_main_returns_zero_on_clean(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    monkeypatch.setattr(reset_mod, "PROJECT_ROOT", root, raising=False)
    monkeypatch.chdir(root)  # default targets resolve relative to cwd, like reset_env.sh (cd root)
    # No runs/ or workspaces/ exist -> nothing to remove, nothing refused -> exit 0.
    assert reset_mod.main([]) == 0


def test_main_returns_nonzero_on_mixed(tmp_path, monkeypatch):
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.setattr(reset_mod, "PROJECT_ROOT", root.resolve(), raising=False)
    good = root / "runs"
    good.mkdir()
    bad = tmp_path / "workspaces"  # outside project root
    bad.mkdir()
    rc = reset_mod.main([str(good), str(bad)])
    assert rc == 1  # one removed, one refused -> overall failure
    assert not good.exists() and bad.exists()


def test_reset_targets_reports_refusals(tmp_path, monkeypatch):
    monkeypatch.setattr(reset_mod, "PROJECT_ROOT", (tmp_path / "proj").resolve(), raising=False)
    (tmp_path / "proj").mkdir()
    result = reset_mod.reset_targets(("/etc/passwd",))
    assert result.refused and not result.ok
