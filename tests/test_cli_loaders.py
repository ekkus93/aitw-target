"""Direct unit tests for the CLI loaders (AITW_TARGET_HARDENING P2.1).

These exercise aitw.cli helpers without a subprocess (complementing the end-to-end tests in
test_cli.py).
"""

import pytest

from aitw.cli import CliError, load_attack_fixture, load_model_config


def test_load_model_config_mock():
    assert load_model_config("mock") == {"adapter": "mock"}


def test_load_model_config_known_tenant():
    # tenant_a is declared in config/tenants.yaml with adapter: mock.
    assert load_model_config("tenant_a")["adapter"] == "mock"


def test_load_model_config_unknown_raises():
    with pytest.raises(CliError):
        load_model_config("definitely_not_a_tenant")


def test_load_attack_fixture_none():
    assert load_attack_fixture(None) is None


def test_load_attack_fixture_missing_raises(tmp_path):
    with pytest.raises(CliError):
        load_attack_fixture(str(tmp_path / "nope.yaml"))


def test_load_attack_fixture_valid(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text("name: x\nmethod: poison_context\npayload: p\n")
    fx = load_attack_fixture(str(f))
    assert fx["method"] == "poison_context"


def test_load_attack_fixture_non_mapping_raises(tmp_path):
    f = tmp_path / "list.yaml"
    f.write_text("- a\n- b\n")
    with pytest.raises(CliError):
        load_attack_fixture(str(f))
