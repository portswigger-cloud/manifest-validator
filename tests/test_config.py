# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from manifest_validator.config import Settings

EXAMPLE = Path(__file__).resolve().parents[1] / "manifest-validator.toml.example"

MINIMAL = {
    "disable-auth": True,
    "check": [{"name": "structural", "kind": "structural"}],
}


def test_the_shipped_example_parses() -> None:
    Settings.from_path(EXAMPLE)


def test_the_example_documents_every_check_kind() -> None:
    with EXAMPLE.open("rb") as handle:
        data = tomllib.load(handle)
    kinds = {check["kind"] for check in data["check"]}
    assert kinds == {"structural", "image-policy", "job"}


def test_defaults_apply() -> None:
    settings = Settings.from_mapping(MINIMAL)
    assert settings.bind_address == "0.0.0.0:8080"
    assert settings.jobs.namespace == "manifest-validator"


def test_at_least_one_check_is_required() -> None:
    with pytest.raises(ValueError, match="at least one"):
        Settings.from_mapping({"disable-auth": True, "check": []})


def test_roles_are_required_unless_auth_is_disabled() -> None:
    with pytest.raises(ValueError, match="disable-auth"):
        Settings.from_mapping({"check": MINIMAL["check"]})


def test_duplicate_check_names_are_rejected() -> None:
    data = {
        "disable-auth": True,
        "check": [
            {"name": "structural", "kind": "structural"},
            {"name": "structural", "kind": "image-policy"},
        ],
    }
    with pytest.raises(ValueError, match="duplicate check names"):
        Settings.from_mapping(data)


def test_a_job_check_must_name_an_image() -> None:
    data = {"disable-auth": True, "check": [{"name": "kics", "kind": "job"}]}
    with pytest.raises(ValueError, match="image is required"):
        Settings.from_mapping(data)


def test_an_unknown_kind_is_rejected() -> None:
    data = {"disable-auth": True, "check": [{"name": "x", "kind": "sorcery"}]}
    with pytest.raises(ValueError, match="kind must be"):
        Settings.from_mapping(data)


def test_non_default_checks_are_excluded_from_the_default_set() -> None:
    data = {
        "disable-auth": True,
        "check": [
            {"name": "structural", "kind": "structural"},
            {"name": "wiz", "kind": "job", "image": "x:1", "default": False},
        ],
    }
    settings = Settings.from_mapping(data)
    assert settings.default_check_names == ("structural",)


def test_a_role_requires_an_issuer_and_audience() -> None:
    data = {"check": MINIMAL["check"], "role": [{"name": "relcoord"}]}
    with pytest.raises(ValueError, match="issuer"):
        Settings.from_mapping(data)


def test_timeout_must_be_positive() -> None:
    data = dict(MINIMAL) | {"jobs": {"timeout-seconds": 0}}
    with pytest.raises(ValueError, match="timeout-seconds"):
        Settings.from_mapping(data)
