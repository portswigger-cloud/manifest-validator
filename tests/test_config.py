# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from manifest_validator.config import Settings

EXAMPLE = Path(__file__).resolve().parents[1] / "manifest-validator.toml.example"

MINIMAL = {"check": [{"name": "structural", "kind": "structural"}]}


def test_the_shipped_example_parses() -> None:
    Settings.from_path(EXAMPLE)


def test_the_example_documents_every_check_kind() -> None:
    with EXAMPLE.open("rb") as handle:
        data = tomllib.load(handle)
    kinds = {check["kind"] for check in data["check"]}
    assert kinds == {"structural", "image-policy", "kics"}


def test_defaults_apply() -> None:
    settings = Settings.from_mapping(MINIMAL)
    assert settings.bind_address == "0.0.0.0:8080"
    assert settings.max_concurrent == 4


def test_at_least_one_check_is_required() -> None:
    with pytest.raises(ValueError, match="at least one"):
        Settings.from_mapping({"check": []})


def test_duplicate_check_names_are_rejected() -> None:
    data = {
        "check": [
            {"name": "structural", "kind": "structural"},
            {"name": "structural", "kind": "image-policy"},
        ],
    }
    with pytest.raises(ValueError, match="duplicate check names"):
        Settings.from_mapping(data)


def test_unknown_severities_are_rejected() -> None:
    data = {
        "check": [
            {"name": "kics", "kind": "kics", "exclude-severities": ["medium", "spicy"]}
        ]
    }
    with pytest.raises(ValueError, match="unknown severities"):
        Settings.from_mapping(data)


def test_excluding_every_severity_is_rejected() -> None:
    data = {
        "check": [
            {
                "name": "kics",
                "kind": "kics",
                "exclude-severities": ["critical", "high", "medium", "low", "info"],
            }
        ]
    }
    with pytest.raises(ValueError, match="could never fail"):
        Settings.from_mapping(data)


def test_an_unknown_kind_is_rejected() -> None:
    data = {"check": [{"name": "x", "kind": "sorcery"}]}
    with pytest.raises(ValueError, match="kind must be"):
        Settings.from_mapping(data)


def test_non_default_checks_are_excluded_from_the_default_set() -> None:
    data = {
        "check": [
            {"name": "structural", "kind": "structural"},
            {"name": "wiz", "kind": "kics", "default": False},
        ],
    }
    settings = Settings.from_mapping(data)
    assert settings.default_check_names == ("structural",)


def test_timeout_must_be_positive() -> None:
    data = {"check": [{"name": "k", "kind": "kics", "timeout-seconds": 0}]}
    with pytest.raises(ValueError, match="timeout-seconds"):
        Settings.from_mapping(data)


def test_max_concurrent_must_be_positive() -> None:
    data = dict(MINIMAL) | {"max-concurrent": 0}
    with pytest.raises(ValueError, match="max-concurrent"):
        Settings.from_mapping(data)
