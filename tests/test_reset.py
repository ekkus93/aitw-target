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
