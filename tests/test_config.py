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


def _kics(*exceptions: dict[str, str]) -> dict[str, object]:
    return {
        "check": [
            {"name": "kics", "kind": "kics", "exception": list(exceptions)},
        ]
    }


def test_an_exception_is_read_onto_the_check() -> None:
    settings = Settings.from_mapping(
        _kics({"source": "crossplane", "query": "RBAC Wildcard In Rule", "reason": "r"})
    )
    exception = settings.checks[0].exceptions[0]
    assert (exception.source, exception.query, exception.reason) == (
        "crossplane",
        "RBAC Wildcard In Rule",
        "r",
    )


def test_an_exception_must_say_why() -> None:
    with pytest.raises(ValueError, match="reason"):
        Settings.from_mapping(_kics({"source": "crossplane", "query": "q"}))


def test_a_bare_source_is_refused() -> None:
    """Accepting a whole release would repeat the thresholds' defect."""
    with pytest.raises(ValueError, match="both source and query"):
        Settings.from_mapping(_kics({"source": "crossplane", "reason": "r"}))


def test_a_bare_query_is_refused() -> None:
    with pytest.raises(ValueError, match="both source and query"):
        Settings.from_mapping(_kics({"query": "RBAC Wildcard In Rule", "reason": "r"}))


def test_a_similarity_id_stands_alone() -> None:
    with pytest.raises(ValueError, match="already identifies a single finding"):
        Settings.from_mapping(
            _kics({"similarity-id": "abc", "source": "x", "query": "q", "reason": "r"})
        )


def test_exceptions_are_meaningless_on_a_non_kics_check() -> None:
    with pytest.raises(ValueError, match="only meaningful"):
        Settings.from_mapping(
            {
                "check": [
                    {
                        "name": "structural",
                        "kind": "structural",
                        "exception": [{"similarity-id": "abc", "reason": "r"}],
                    }
                ]
            }
        )
