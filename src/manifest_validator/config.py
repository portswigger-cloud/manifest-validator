# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from manifest_validator.auth import RoleConfig

logger = logging.getLogger(__name__)

CheckKind = Literal["structural", "image-policy", "job"]


@dataclass(frozen=True)
class JobSettings:
    namespace: str = "manifest-validator"
    timeout_seconds: int = 600
    max_concurrent: int = 4
    tree_base_url: str = "http://manifest-validator:8080"
    fetcher_image: str = "public.ecr.aws/docker/library/alpine:3.22"
    token_audience: str = "manifest-validator"

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> JobSettings:
        settings = cls(
            namespace=_string(data, "namespace", cls.namespace),
            timeout_seconds=_int(data, "timeout-seconds", cls.timeout_seconds),
            max_concurrent=_int(data, "max-concurrent", cls.max_concurrent),
            tree_base_url=_string(data, "tree-base-url", cls.tree_base_url),
            fetcher_image=_string(data, "fetcher-image", cls.fetcher_image),
            token_audience=_string(data, "token-audience", cls.token_audience),
        )
        if settings.timeout_seconds <= 0:
            raise ValueError("jobs.timeout-seconds must be positive")
        if settings.max_concurrent <= 0:
            raise ValueError("jobs.max-concurrent must be positive")
        return settings


@dataclass(frozen=True)
class CheckConfig:
    """A check the service is willing to run.

    Checks are defined here and named — never described — by callers. A request
    carries opaque check names, so no request can ever choose an image to
    execute.
    """

    name: str
    kind: CheckKind
    image: str | None = None
    args: tuple[str, ...] = ()
    tool_version: str = "unknown"
    ruleset_digest: str = "unknown"
    findings_format: str = "exit-code"
    service_account: str | None = None
    allow_egress: bool = False
    allowed_registries: tuple[str, ...] = ()
    require_pinned: bool = True
    env: dict[str, str] = field(default_factory=dict)
    default: bool = True

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> CheckConfig:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("check.name must be a non-empty string")
        kind = data.get("kind")
        if kind not in ("structural", "image-policy", "job"):
            raise ValueError(
                f"check.{name}.kind must be 'structural', 'image-policy' or 'job'"
            )
        image = data.get("image")
        if kind == "job" and (not isinstance(image, str) or not image.strip()):
            raise ValueError(f"check.{name}.image is required when kind = 'job'")
        return cls(
            name=name,
            kind=kind,
            image=image if isinstance(image, str) else None,
            args=_string_tuple(data, "args"),
            tool_version=_string(data, "tool-version", cls.tool_version),
            ruleset_digest=_string(data, "ruleset-digest", cls.ruleset_digest),
            findings_format=_string(data, "findings-format", cls.findings_format),
            service_account=data.get("service-account"),
            allow_egress=_bool(data, "allow-egress", cls.allow_egress),
            allowed_registries=_string_tuple(data, "allowed-registries"),
            require_pinned=_bool(data, "require-pinned", cls.require_pinned),
            env=dict(data.get("env", {})),
            default=_bool(data, "default", cls.default),
        )


@dataclass(frozen=True)
class Settings:
    bind_address: str = "0.0.0.0:8080"
    disable_auth: bool = False
    jobs: JobSettings = field(default_factory=JobSettings)
    checks: tuple[CheckConfig, ...] = ()
    roles: tuple[RoleConfig, ...] = ()

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
        roles = tuple(RoleConfig.from_mapping(entry) for entry in data.get("role", []))
        settings = cls(
            bind_address=_string(data, "bind-address", cls.bind_address),
            disable_auth=_bool(data, "disable-auth", cls.disable_auth),
            jobs=JobSettings.from_mapping(data.get("jobs", {})),
            checks=checks,
            roles=roles,
        )
        if not settings.disable_auth and not roles:
            raise ValueError("at least one [[role]] is required unless disable-auth")
        return settings

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
