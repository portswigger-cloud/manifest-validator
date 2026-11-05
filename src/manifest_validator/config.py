# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import logging
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

CheckKind = Literal["structural", "image-policy", "kics", "image-exists"]

CHECK_KINDS: tuple[CheckKind, ...] = (
    "structural",
    "image-policy",
    "kics",
    "image-exists",
)

RegistryAuth = Literal["anonymous", "basic", "ecr"]

REGISTRY_AUTHS: tuple[RegistryAuth, ...] = ("anonymous", "basic", "ecr")

KICS_SEVERITIES = ("critical", "high", "medium", "low", "info")

# <account>.dkr.ecr.<region>.amazonaws.com: the account and region are what an
# authorization token is asked for, so an `ecr` registry has to spell both.
_ECR_HOST = re.compile(r"(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com")

# A typo in an excluded id would silently exclude nothing, and nothing would ever
# report it: the queries it names are the ones that stop being asked.
_QUERY_ID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")


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
class RegistryConfig:
    """A registry the image-exists check may contact, and how it authenticates.

    The list is the whole of what the check talks to. An image on a registry
    that is not declared is a finding, not a request: the tree is written by
    whoever opened the pull request, so it must not be able to choose a host to
    send a credential to, or the service to call out to one.
    """

    host: str
    auth: RegistryAuth = "anonymous"
    username_file: str | None = None
    password_file: str | None = None
    """Read on every token request rather than once, so a rotated Secret takes
    effect without a restart."""

    mirror_of: str | None = None
    """A pull-through proxy this service cannot reach, checked at its upstream.

    The proxy serves what the upstream has, so asking the upstream is the same
    question. The upstream has to be declared in its own right.
    """

    @property
    def ecr_account(self) -> str:
        match = _ECR_HOST.fullmatch(self.host)
        if match is None:
            raise ValueError(f"{self.host} is not an ECR registry host")
        return match.group(1)

    @property
    def ecr_region(self) -> str:
        match = _ECR_HOST.fullmatch(self.host)
        if match is None:
            raise ValueError(f"{self.host} is not an ECR registry host")
        return match.group(2)

    def describe(self) -> str:
        if self.mirror_of:
            return f"{self.host} (mirror of {self.mirror_of})"
        return f"{self.host} ({self.auth})"

    @classmethod
    def from_mapping(cls, check_name: str, data: dict[str, Any]) -> RegistryConfig:
        where = f"check.{check_name}.registry"
        host = _optional_string(data, "host", where)
        if host is None:
            raise ValueError(f"{where}.host is required")
        if "/" in host or host != host.strip().lower():
            raise ValueError(
                f"{where}.host {host!r} must be a bare lower-case host, as an image "
                "reference spells it, without a scheme or path"
            )
        where = f"{where}[{host}]"
        mirror_of = _optional_string(data, "mirror-of", where)
        auth = data.get("auth", "anonymous")
        if auth not in REGISTRY_AUTHS:
            raise ValueError(f"{where}.auth must be one of {list(REGISTRY_AUTHS)}")
        if mirror_of is not None and "auth" in data:
            raise ValueError(
                f"{where} sets auth together with mirror-of; a mirror is checked "
                "with its upstream's credentials"
            )
        username_file = _optional_string(data, "username-file", where)
        password_file = _optional_string(data, "password-file", where)
        if auth == "basic":
            if username_file is None or password_file is None:
                raise ValueError(
                    f"{where} uses basic auth, so it needs username-file and "
                    "password-file"
                )
        elif username_file is not None or password_file is not None:
            raise ValueError(
                f"{where} sets credential files, which only basic auth reads"
            )
        if auth == "ecr" and _ECR_HOST.fullmatch(host) is None:
            raise ValueError(
                f"{where} uses ecr auth, so host must be "
                "<account>.dkr.ecr.<region>.amazonaws.com"
            )
        return cls(
            host=host,
            auth=auth,
            username_file=username_file,
            password_file=password_file,
            mirror_of=mirror_of,
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
    exclude_queries: tuple[str, ...] = ()
    """Queries the scanner does not run.

    An exception says a finding was read and accepted; this says the question is
    not worth asking of these trees. The difference matters on review: an
    exception that stops matching is reported, an excluded query is silent by
    construction, so the reason has to carry its own justification.
    """
    timeout_seconds: int = 600
    allowed_registries: tuple[str, ...] = ()
    require_pinned: bool = True
    default: bool = True
    exceptions: tuple[PolicyException, ...] = ()
    registries: tuple[RegistryConfig, ...] = ()
    cache_ttl_minutes: int = 60
    """How long an image found to exist is believed to, digests included: an
    image pinned by digest can still be deleted, by a lifecycle policy if
    nobody else."""

    request_timeout_seconds: int = 10
    attempts: int = 3
    """Tries per registry request before a timeout, 429 or 5xx becomes a finding."""

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> CheckConfig:
        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("check.name must be a non-empty string")
        kind = data.get("kind")
        if kind not in CHECK_KINDS:
            raise ValueError(f"check.{name}.kind must be one of {list(CHECK_KINDS)}")
        exclude_queries = _string_tuple(data, "exclude-queries")
        if exclude_queries and kind != "kics":
            raise ValueError(
                f"check.{name}.exclude-queries is only meaningful for a 'kics' check"
            )
        malformed = [q for q in exclude_queries if not _QUERY_ID.fullmatch(q)]
        if malformed:
            raise ValueError(
                f"check.{name}.exclude-queries has ids that are not query uuids "
                f"{sorted(malformed)}; read them off a verdict's rule id"
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
        registries = _registries(name, kind, data)
        cache_ttl_minutes = _int(data, "cache-ttl-minutes", cls.cache_ttl_minutes)
        request_timeout_seconds = _int(
            data, "request-timeout-seconds", cls.request_timeout_seconds
        )
        attempts = _int(data, "attempts", cls.attempts)
        for key, value in (
            ("cache-ttl-minutes", cache_ttl_minutes),
            ("request-timeout-seconds", request_timeout_seconds),
            ("attempts", attempts),
        ):
            if key in data and kind != "image-exists":
                raise ValueError(
                    f"check.{name}.{key} is only meaningful for an 'image-exists' check"
                )
            if value <= 0:
                raise ValueError(f"check.{name}.{key} must be positive")
        return cls(
            name=name,
            kind=kind,
            types=_string_tuple(data, "types"),
            exclude_severities=exclude_severities,
            exclude_queries=exclude_queries,
            timeout_seconds=timeout_seconds,
            allowed_registries=_string_tuple(data, "allowed-registries"),
            require_pinned=_bool(data, "require-pinned", cls.require_pinned),
            default=_bool(data, "default", cls.default),
            exceptions=exceptions,
            registries=registries,
            cache_ttl_minutes=cache_ttl_minutes,
            request_timeout_seconds=request_timeout_seconds,
            attempts=attempts,
        )


def _registries(
    check_name: str, kind: str, data: dict[str, Any]
) -> tuple[RegistryConfig, ...]:
    raw = data.get("registry", [])
    if not isinstance(raw, list) or not all(isinstance(r, dict) for r in raw):
        raise ValueError(f"check.{check_name}.registry must be a list of tables")
    if kind != "image-exists":
        if raw:
            raise ValueError(
                f"check.{check_name}.registry is only meaningful for an "
                "'image-exists' check"
            )
        return ()
    if not raw:
        raise ValueError(
            f"check.{check_name} declares no registry, so every image would be "
            "a finding"
        )
    registries = tuple(RegistryConfig.from_mapping(check_name, r) for r in raw)
    hosts = [r.host for r in registries]
    duplicates = sorted({h for h in hosts if hosts.count(h) > 1})
    if duplicates:
        raise ValueError(f"check.{check_name} declares {duplicates} more than once")
    by_host = {r.host: r for r in registries}
    for registry in registries:
        if registry.mirror_of is None:
            continue
        upstream = by_host.get(registry.mirror_of)
        if upstream is None:
            raise ValueError(
                f"check.{check_name}.registry[{registry.host}] is a mirror of "
                f"{registry.mirror_of}, which is not declared"
            )
        if upstream.mirror_of is not None:
            raise ValueError(
                f"check.{check_name}.registry[{registry.host}] is a mirror of "
                f"another mirror, {registry.mirror_of}"
            )
    return registries


@dataclass(frozen=True)
class ScanCacheSettings:
    """Where scanners' findings are remembered beyond this process.

    Without it they are remembered in memory, and a restart rescans everything.
    """

    table_name: str
    region_name: str | None = None
    endpoint_url: str | None = None
    ttl_days: int = 30

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> ScanCacheSettings:
        where = "scan-cache"
        table_name = _optional_string(data, "table-name", where)
        if table_name is None:
            raise ValueError(f"{where}.table-name is required")
        ttl_days = _int(data, "ttl-days", cls.ttl_days)
        if ttl_days <= 0:
            raise ValueError(f"{where}.ttl-days must be positive")
        return cls(
            table_name=table_name,
            region_name=_optional_string(data, "region-name", where),
            endpoint_url=_optional_string(data, "endpoint-url", where),
            ttl_days=ttl_days,
        )


@dataclass(frozen=True)
class Settings:
    bind_address: str = "0.0.0.0:8080"
    max_concurrent: int = 4
    checks: tuple[CheckConfig, ...] = ()
    scan_cache: ScanCacheSettings | None = None

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
        scan_cache = data.get("scan-cache")
        if scan_cache is not None and not isinstance(scan_cache, dict):
            raise ValueError("scan-cache must be a table")
        return cls(
            bind_address=_string(data, "bind-address", cls.bind_address),
            max_concurrent=max_concurrent,
            checks=checks,
            scan_cache=(
                ScanCacheSettings.from_mapping(scan_cache)
                if scan_cache is not None
                else None
            ),
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
