# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

CheckKind = Literal["structural", "image-policy", "kics"]

KICS_SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class PolicyException:
    """One KICS finding, or one class of them, that does not fail a verdict.

    Keyed on provenance rather than on a count: `source` is the release that
    produced the file, as recorded in the manifest's `# Source:` header, so an
    exception survives a chart upgrade but cannot spread to another release.
    `similarity_id` is the escape hatch for a genuine one-off.

    A bare `source` is refused. Accepting every query from a release would
    inherit the defect the thresholds have — a widening nobody reads.
    """

    reason: str
    source: str | None = None
    query: str | None = None
    similarity_id: str | None = None

    def describe(self) -> str:
        if self.similarity_id:
            return f"similarity-id {self.similarity_id}"
        return f"{self.query} in {self.source}"

    @classmethod
    def from_mapping(cls, check_name: str, data: dict[str, Any]) -> PolicyException:
        where = f"check.{check_name}.exception"
        reason = data.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"{where}.reason must be a non-empty string")
        source = _optional_string(data, "source", where)
        query = _optional_string(data, "query", where)
        similarity_id = _optional_string(data, "similarity-id", where)
        if similarity_id:
            if source or query:
                raise ValueError(
                    f"{where} sets similarity-id together with source/query; a "
                    "similarity-id already identifies a single finding"
                )
        elif not (source and query):
            raise ValueError(
                f"{where} must set either similarity-id, or both source and query"
            )
        return cls(
            reason=reason, source=source, query=query, similarity_id=similarity_id
        )


@dataclass(frozen=True)
class CheckConfig:
    """A check the service is willing to run.

    Checks are defined here and named — never described — by callers. A request
    carries opaque check names, so no request can ever choose a command to
    execute.
    """

    name: str
    kind: CheckKind
    types: tuple[str, ...] = ()
    exclude_severities: tuple[str, ...] = ()
    timeout_seconds: int = 600
    allowed_registries: tuple[str, ...] = ()
    require_pinned: bool = True
    default: bool = True
    advisory: bool = False
    """Whether this check reports its findings without failing the verdict.

    Somewhere for a check to sit while its findings are being worked through:
    every finding is reported, and a caller that gates on ``passed`` deploys
    anyway. It belongs here rather than in the caller's config, because whether
    a finding stops a deployment is this service's decision to make.

    A check left advisory indefinitely is one nobody is acting on.
    """
    exceptions: tuple[PolicyException, ...] = ()

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> CheckConfig:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("check.name must be a non-empty string")
        kind = data.get("kind")
        if kind not in ("structural", "image-policy", "kics"):
            raise ValueError(
                f"check.{name}.kind must be 'structural', 'image-policy' or 'kics'"
            )
        exclude_severities = _string_tuple(data, "exclude-severities")
        unknown = [s for s in exclude_severities if s not in KICS_SEVERITIES]
        if unknown:
            raise ValueError(
                f"check.{name}.exclude-severities has unknown severities "
                f"{sorted(unknown)}; expected some of {list(KICS_SEVERITIES)}"
            )
        if set(exclude_severities) == set(KICS_SEVERITIES):
            raise ValueError(
                f"check.{name}.exclude-severities excludes every severity, so the "
                "check could never fail"
            )
        timeout_seconds = _int(data, "timeout-seconds", cls.timeout_seconds)
        if timeout_seconds <= 0:
            raise ValueError(f"check.{name}.timeout-seconds must be positive")
        raw_exceptions = data.get("exception", [])
        if not isinstance(raw_exceptions, list):
            raise ValueError(f"check.{name}.exception must be a list of tables")
        if raw_exceptions and kind != "kics":
            raise ValueError(
                f"check.{name}.exception is only meaningful for a 'kics' check"
            )
        exceptions = tuple(
            PolicyException.from_mapping(name, entry) for entry in raw_exceptions
        )
        return cls(
            name=name,
            kind=kind,
            types=_string_tuple(data, "types"),
            exclude_severities=exclude_severities,
            timeout_seconds=timeout_seconds,
            allowed_registries=_string_tuple(data, "allowed-registries"),
            require_pinned=_bool(data, "require-pinned", cls.require_pinned),
            default=_bool(data, "default", cls.default),
            advisory=_bool(data, "advisory", cls.advisory),
            exceptions=exceptions,
        )


@dataclass(frozen=True)
class Settings:
    bind_address: str = "0.0.0.0:8080"
    max_concurrent: int = 4
    checks: tuple[CheckConfig, ...] = ()

    @classmethod
    def from_path(cls, path: Path) -> Settings:
        with path.open("rb") as handle:
            return cls.from_mapping(tomllib.load(handle))

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Settings:
        checks = tuple(
            CheckConfig.from_mapping(entry) for entry in data.get("check", [])
        )
        if not checks:
            raise ValueError("at least one [[check]] is required")
        duplicates = {
            c.name for c in checks if [x.name for x in checks].count(c.name) > 1
        }
        if duplicates:
            raise ValueError(f"duplicate check names: {sorted(duplicates)}")
        max_concurrent = _int(data, "max-concurrent", cls.max_concurrent)
        if max_concurrent <= 0:
            raise ValueError("max-concurrent must be positive")
        return cls(
            bind_address=_string(data, "bind-address", cls.bind_address),
            max_concurrent=max_concurrent,
            checks=checks,
        )

    @property
    def default_check_names(self) -> tuple[str, ...]:
        return tuple(check.name for check in self.checks if check.default)

    @property
    def advisory_check_names(self) -> tuple[str, ...]:
        return tuple(check.name for check in self.checks if check.advisory)


def _string(data: dict[str, Any], key: str, default: str) -> str:
    value = data.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _int(data: dict[str, Any], key: str, default: int) -> int:
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    return value


def _bool(data: dict[str, Any], key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _optional_string(data: dict[str, Any], key: str, where: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}.{key} must be a non-empty string")
    return value


def _string_tuple(data: dict[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{key} must be a list of strings")
    return tuple(value)
