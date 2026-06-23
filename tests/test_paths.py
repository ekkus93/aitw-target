"""Tests for the shared path-containment helper (AITW_TARGET_HARDENING P2.2)."""

import pytest

from aitw.safety.paths import is_within, resolve_under


def test_is_within_true_for_child_and_root(tmp_path):
    assert is_within(tmp_path, tmp_path / "a" / "b")
    assert is_within(tmp_path, tmp_path)  # root itself counts as within


def test_is_within_false_for_escape(tmp_path):
    assert not is_within(tmp_path / "root", tmp_path / "root" / ".." / "sibling")


def test_resolve_under_returns_resolved_child(tmp_path):
    out = resolve_under(tmp_path, tmp_path / "a")
    assert out == (tmp_path / "a").resolve()


def test_resolve_under_rejects_escape(tmp_path):
    with pytest.raises(ValueError):
        resolve_under(tmp_path / "root", tmp_path / "root" / ".." / "escape")
