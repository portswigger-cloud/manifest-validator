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
    assert kinds == {"structural", "image-policy", "kics", "image-exists"}


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


def test_excluded_queries_are_read_onto_the_check() -> None:
    query = "3e2d3b2f-c22a-4df1-9cc6-a7a0aebb0c99"
    settings = Settings.from_mapping(
        {"check": [{"name": "kics", "kind": "kics", "exclude-queries": [query]}]}
    )
    assert settings.checks[0].exclude_queries == (query,)


def test_a_malformed_query_id_is_refused() -> None:
    """An id that matches nothing would exclude nothing, silently."""
    with pytest.raises(ValueError, match="not query uuids"):
        Settings.from_mapping(
            {
                "check": [
                    {
                        "name": "kics",
                        "kind": "kics",
                        "exclude-queries": ["Passwords And Secrets"],
                    }
                ]
            }
        )


def test_excluded_queries_are_meaningless_on_a_non_kics_check() -> None:
    with pytest.raises(ValueError, match="only meaningful"):
        Settings.from_mapping(
            {
                "check": [
                    {
                        "name": "structural",
                        "kind": "structural",
                        "exclude-queries": ["3e2d3b2f-c22a-4df1-9cc6-a7a0aebb0c99"],
                    }
                ]
            }
        )


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


def test_scans_are_remembered_in_memory_unless_a_table_is_named() -> None:
    assert Settings.from_mapping(MINIMAL).scan_cache is None


def test_a_scan_cache_table_is_read() -> None:
    settings = Settings.from_mapping(
        MINIMAL | {"scan-cache": {"table-name": "t", "ttl-days": 7}}
    )
    assert settings.scan_cache is not None
    assert settings.scan_cache.table_name == "t"
    assert settings.scan_cache.ttl_days == 7


def test_a_scan_cache_without_a_table_is_rejected() -> None:
    with pytest.raises(ValueError, match="table-name"):
        Settings.from_mapping(MINIMAL | {"scan-cache": {}})


def test_a_scan_cache_ttl_must_be_positive() -> None:
    with pytest.raises(ValueError, match="ttl-days"):
        Settings.from_mapping(
            MINIMAL | {"scan-cache": {"table-name": "t", "ttl-days": 0}}
        )


def _image_exists(*registries: dict[str, str], **options: object) -> dict[str, object]:
    check: dict[str, object] = {
        "name": "image-exists",
        "kind": "image-exists",
        "registry": list(registries),
    }
    return {"check": [check | options]}


def test_registries_are_read_onto_an_image_exists_check() -> None:
    settings = Settings.from_mapping(
        _image_exists(
            {"host": "quay.io"},
            {
                "host": "registry.wiz.io",
                "auth": "basic",
                "username-file": "/wiz/username",
                "password-file": "/wiz/password",
            },
            {"host": "123456789012.dkr.ecr.eu-west-1.amazonaws.com", "auth": "ecr"},
            {"host": "docker.io"},
            {"host": "mirror.example", "mirror-of": "docker.io"},
            **{"cache-ttl-minutes": 30, "attempts": 5},
        )
    )
    (check,) = settings.checks
    assert [r.host for r in check.registries] == [
        "quay.io",
        "registry.wiz.io",
        "123456789012.dkr.ecr.eu-west-1.amazonaws.com",
        "docker.io",
        "mirror.example",
    ]
    assert check.registries[0].auth == "anonymous"
    assert check.registries[2].ecr_account == "123456789012"
    assert check.registries[2].ecr_region == "eu-west-1"
    assert (check.cache_ttl_minutes, check.attempts) == (30, 5)


def test_an_image_exists_check_needs_a_registry() -> None:
    with pytest.raises(ValueError, match="declares no registry"):
        Settings.from_mapping(_image_exists())


def test_a_registry_declared_twice_is_rejected() -> None:
    with pytest.raises(ValueError, match="more than once"):
        Settings.from_mapping(_image_exists({"host": "quay.io"}, {"host": "quay.io"}))


@pytest.mark.parametrize("host", ["https://quay.io", "quay.io/org", "Quay.io"])
def test_a_registry_host_is_bare(host: str) -> None:
    with pytest.raises(ValueError, match="bare lower-case host"):
        Settings.from_mapping(_image_exists({"host": host}))


def test_an_unknown_auth_is_rejected() -> None:
    with pytest.raises(ValueError, match="auth must be one of"):
        Settings.from_mapping(_image_exists({"host": "quay.io", "auth": "token"}))


def test_basic_auth_needs_both_files() -> None:
    with pytest.raises(ValueError, match="username-file and password-file"):
        Settings.from_mapping(
            _image_exists({"host": "quay.io", "auth": "basic", "password-file": "/p"})
        )


def test_credential_files_are_only_for_basic_auth() -> None:
    with pytest.raises(ValueError, match="only basic auth reads"):
        Settings.from_mapping(_image_exists({"host": "quay.io", "password-file": "/p"}))


def test_ecr_auth_needs_an_ecr_host() -> None:
    with pytest.raises(ValueError, match="dkr.ecr"):
        Settings.from_mapping(_image_exists({"host": "quay.io", "auth": "ecr"}))


def test_a_mirror_of_an_undeclared_registry_is_rejected() -> None:
    with pytest.raises(ValueError, match="not declared"):
        Settings.from_mapping(
            _image_exists({"host": "mirror.example", "mirror-of": "docker.io"})
        )


def test_a_mirror_takes_its_upstream_credential() -> None:
    with pytest.raises(ValueError, match="mirror-of"):
        Settings.from_mapping(
            _image_exists(
                {"host": "docker.io"},
                {
                    "host": "mirror.example",
                    "mirror-of": "docker.io",
                    "auth": "anonymous",
                },
            )
        )


def test_registries_are_meaningless_on_another_kind() -> None:
    data = {
        "check": [
            {"name": "s", "kind": "structural", "registry": [{"host": "quay.io"}]}
        ]
    }
    with pytest.raises(ValueError, match="only meaningful"):
        Settings.from_mapping(data)


def test_image_exists_options_are_meaningless_on_another_kind() -> None:
    data = {"check": [{"name": "s", "kind": "structural", "attempts": 2}]}
    with pytest.raises(ValueError, match="only meaningful"):
        Settings.from_mapping(data)


@pytest.mark.parametrize(
    "key", ["cache-ttl-minutes", "request-timeout-seconds", "attempts"]
)
def test_image_exists_options_must_be_positive(key: str) -> None:
    with pytest.raises(ValueError, match=key):
        Settings.from_mapping(_image_exists({"host": "quay.io"}, **{key: 0}))
