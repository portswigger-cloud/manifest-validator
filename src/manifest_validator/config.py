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
        return cls(
            name=name,
            kind=kind,
            types=_string_tuple(data, "types"),
            exclude_severities=exclude_severities,
            timeout_seconds=timeout_seconds,
            allowed_registries=_string_tuple(data, "allowed-registries"),
            require_pinned=_bool(data, "require-pinned", cls.require_pinned),
            default=_bool(data, "default", cls.default),
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


def _string_tuple(data: dict[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{key} must be a list of strings")
    return tuple(value)
