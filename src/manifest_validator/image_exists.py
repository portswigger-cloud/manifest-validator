# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
"""Does every image a tree references exist in its registry?

A tree that renders and passes every other check can still name a tag nobody
pushed, and that only shows up once Argo has synced it, as ImagePullBackOff.
This asks each registry for the manifest itself, the same `HEAD` a runtime's
pull starts with, and pulls nothing.

Only declared registries are contacted. The tree is written by whoever opened
the pull request, so an image on any other host is reported without a request
being made, and a credential is only ever offered to the registry it was
declared for: never to a host a redirect led to.

Unlike the other checks the answer is not a function of the tree. An image
missing today can be pushed tomorrow and deleted the day after, so verdicts are
not remembered, and an image found to exist is believed to only for a while.
"""

from __future__ import annotations

import base64
import logging
import re
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx

from manifest_validator.checks import ProgressSink, image_references, ruleset_digest
from manifest_validator.config import RegistryConfig
from manifest_validator.errors import RegistryCredentialError, RegistryUnreachable
from manifest_validator.models import Finding, Severity, Tree, Verdict

logger = logging.getLogger(__name__)

DOCKER_HUB = "docker.io"
# References spell Docker Hub three ways, and its API answers at none of them.
_DOCKER_HUB_ALIASES = frozenset(
    {"docker.io", "index.docker.io", "registry-1.docker.io"}
)
_DOCKER_HUB_API = "registry-1.docker.io"

# Every manifest a runtime might be served for a reference. Without the index
# types some registries answer 404 for an image that only exists multi-arch.
MANIFEST_MEDIA_TYPES = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)

_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_BACKOFF_SECONDS = 10.0
# ECR tokens last twelve hours; one about to lapse is replaced early rather than
# risk it expiring between being read and being used.
_ECR_REFRESH_MARGIN_SECONDS = 1800.0
# What the distribution token specification says a token lasts when its response
# does not say, as public ECR's never do.
_DEFAULT_TOKEN_LIFETIME_SECONDS = 60.0
# A bearer token about to lapse is not sent: it could expire on the way.
_TOKEN_REFRESH_MARGIN_SECONDS = 10.0
_MAX_TOKENS = 1024

_REPOSITORY = re.compile(
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
)
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128}")
_CHALLENGE = re.compile(r"\s*(\w+)\s+(.*)")
_CHALLENGE_PARAM = re.compile(r'(\w+)="([^"]*)"')

Outcome = Literal["found", "missing", "denied", "unverifiable"]


@dataclass(frozen=True)
class ImageReference:
    """An image reference, resolved the way a container runtime resolves it."""

    original: str
    registry: str
    """Docker Hub is `docker.io` however the reference spelled it."""
    repository: str
    """`library/redis` for a bare `redis`."""
    reference: str
    """The digest when there is one, which is what a runtime pulls, else the tag."""

    @property
    def key(self) -> str:
        separator = "@" if _DIGEST.fullmatch(self.reference) else ":"
        return f"{self.registry}/{self.repository}{separator}{self.reference}"


def parse_reference(text: str) -> ImageReference:
    """Resolve a reference, raising ValueError for one no runtime would pull."""
    name, at, digest = text.strip().partition("@")
    if at and not _DIGEST.fullmatch(digest):
        raise ValueError(f"{digest!r} is not a sha256 or sha512 digest")
    tag: str | None = None
    if name.rfind(":") > name.rfind("/"):
        name, _, tag = name.rpartition(":")
        if not _TAG.fullmatch(tag):
            raise ValueError(f"{tag!r} is not a valid tag")
    first, slash, rest = name.partition("/")
    if slash and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first, rest
    else:
        registry, repository = DOCKER_HUB, name
    if registry in _DOCKER_HUB_ALIASES:
        registry = DOCKER_HUB
        if "/" not in repository:
            repository = f"library/{repository}"
    if not _REPOSITORY.fullmatch(repository):
        raise ValueError(f"{repository!r} is not a valid repository name")
    return ImageReference(
        original=text,
        registry=registry,
        repository=repository,
        reference=digest if at else (tag or "latest"),
    )


def api_host(registry: str) -> str:
    return _DOCKER_HUB_API if registry == DOCKER_HUB else registry


@dataclass(frozen=True)
class Lookup:
    outcome: Outcome
    detail: str = ""


@dataclass(frozen=True)
class Verification:
    """What a registry made of its credential when the service started."""

    registry: str
    outcome: Literal["ok", "rejected", "unreachable"]
    detail: str


@dataclass(frozen=True)
class EcrToken:
    username: str
    password: str
    expires_at: float
    """Seconds since the epoch."""


class EcrTokenSource(Protocol):
    def token(self, region: str) -> EcrToken: ...


class Boto3EcrTokens:
    """ECR authorization tokens for this service's own IAM role.

    One token per region reads every registry in it that the role may read,
    other accounts' included: whether it may is the repository policy's say.
    """

    def __init__(self) -> None:
        self._clients: dict[str, Any] = {}
        self._lock = threading.Lock()

    def token(self, region: str) -> EcrToken:
        import boto3
        from botocore.exceptions import (
            BotoCoreError,
            ClientError,
            ConnectionClosedError,
            ConnectTimeoutError,
            EndpointConnectionError,
            ReadTimeoutError,
        )

        with self._lock:
            client = self._clients.get(region)
            if client is None:
                client = boto3.client("ecr", region_name=region)
                self._clients[region] = client
        try:
            data = client.get_authorization_token()["authorizationData"][0]
        except (
            ConnectionClosedError,
            ConnectTimeoutError,
            EndpointConnectionError,
            ReadTimeoutError,
        ) as exc:
            # Not reaching STS or ECR says nothing about the role.
            raise RegistryUnreachable(
                f"cannot reach AWS for an ECR token in {region}: {exc}"
            ) from exc
        except (BotoCoreError, ClientError) as exc:
            raise RegistryCredentialError(
                f"no ECR authorization token for {region}: {exc}"
            ) from exc
        username, _, password = (
            base64.b64decode(data["authorizationToken"]).decode().partition(":")
        )
        return EcrToken(username, password, data["expiresAt"].timestamp())


class RegistryCredentials:
    """The username and password each declared registry is offered, if any."""

    def __init__(
        self, ecr: EcrTokenSource, clock: Callable[[], float] = time.time
    ) -> None:
        self._ecr = ecr
        self._clock = clock
        self._ecr_tokens: dict[str, EcrToken] = {}
        self._lock = threading.Lock()

    def basic(self, registry: RegistryConfig) -> tuple[str, str] | None:
        """Raises RegistryCredentialError for a credential that should exist."""
        if registry.auth == "basic":
            return (
                _read_secret(registry.username_file),
                _read_secret(registry.password_file),
            )
        if registry.auth == "ecr":
            token = self._ecr_token(registry.ecr_region)
            return token.username, token.password
        return None

    def _ecr_token(self, region: str) -> EcrToken:
        with self._lock:
            token = self._ecr_tokens.get(region)
            if (
                token is None
                or token.expires_at - _ECR_REFRESH_MARGIN_SECONDS <= self._clock()
            ):
                token = self._ecr.token(region)
                self._ecr_tokens[region] = token
            return token


def _read_secret(path: str | None) -> str:
    if path is None:
        raise RegistryCredentialError("no credential file is configured")
    try:
        value = Path(path).read_text().strip()
    except OSError as exc:
        raise RegistryCredentialError(f"cannot read {path}: {exc}") from exc
    if not value:
        raise RegistryCredentialError(f"{path} is empty")
    return value


class _Unverifiable(Exception):
    """No answer worth classifying: a transport failure, or retries ran out."""


class _Rejected(Exception):
    """A token endpoint refused the credential it was offered."""


class RegistryClient:
    """Asks registries whether a manifest exists, over the v2 distribution API."""

    def __init__(
        self,
        credentials: RegistryCredentials,
        *,
        http: httpx.Client,
        attempts: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._credentials = credentials
        self._http = http
        self._attempts = attempts
        self._sleep = sleep
        self._clock = clock
        # Each bearer token, and the clock reading after which it is not sent.
        self._tokens: dict[tuple[str, str], tuple[str, float]] = {}
        self._lock = threading.Lock()

    def lookup(self, image: ImageReference, registry: RegistryConfig) -> Lookup:
        try:
            credential = self._credentials.basic(registry)
        except (RegistryCredentialError, RegistryUnreachable) as exc:
            return Lookup("unverifiable", f"the {registry.auth} credential: {exc}")
        api = api_host(registry.host)
        url = httpx.URL(
            f"https://{api}/v2/{image.repository}/manifests/{image.reference}"
        )
        try:
            remembered = self._remembered(api, image.repository)
            response = self._send(
                "HEAD", url, remembered or self._authorization(registry, credential)
            )
            if remembered is not None and response.status_code not in (200, 401, 404):
                # Not every registry answers a token it no longer honours with the
                # 401 that starts the token flow again: public ECR answers 400. So
                # a remembered token is the first suspect, and the lookup is made
                # once more without it.
                self._forget(api, image.repository)
                response = self._send(
                    "HEAD", url, self._authorization(registry, credential)
                )
            if response.status_code == 401:
                # After a redirect it is the host that challenged that has to be
                # answered, and only the declared registry is ever offered the
                # credential.
                challenged = response.url
                offered = credential if challenged.host == api else None
                authorization = self._authorize(response, image.repository, offered)
                if authorization is not None:
                    response = self._send("HEAD", challenged, authorization)
        except _Rejected as exc:
            return Lookup("denied", str(exc))
        except _Unverifiable as exc:
            return Lookup("unverifiable", str(exc))
        status = response.status_code
        if status == 200:
            return Lookup("found")
        if status == 404:
            return Lookup("missing", f"{response.url.host} answered 404")
        if status in (401, 403):
            return Lookup("denied", f"{response.url.host} answered {status}")
        return Lookup("unverifiable", f"{response.url.host} answered {status}")

    def verify(self, registry: RegistryConfig) -> Verification:
        """Whether a registry accepts its credential, before any tree needs it.

        Only a refusal of a credential is `rejected`. A registry that cannot be
        reached says nothing about the credential, and is `unreachable`.
        """
        host = registry.host
        if registry.mirror_of is not None:
            return Verification(host, "ok", f"checked at {registry.mirror_of}")
        try:
            credential = self._credentials.basic(registry)
        except RegistryCredentialError as exc:
            return Verification(host, "rejected", str(exc))
        except RegistryUnreachable as exc:
            return Verification(host, "unreachable", str(exc))
        api = api_host(host)
        url = httpx.URL(f"https://{api}/v2/")
        authorization = (
            _basic(credential)
            if registry.auth == "ecr" and credential is not None
            else None
        )
        try:
            response = self._send("GET", url, authorization)
            if response.status_code == 401 and credential is not None:
                if authorization is not None:
                    return Verification(host, "rejected", f"{api} answered 401")
                challenge = _challenge(response)
                if challenge is None:
                    return Verification(
                        host, "rejected", f"{api} answered 401 without a challenge"
                    )
                scheme, params = challenge
                if scheme == "basic":
                    response = self._send("GET", url, _basic(credential))
                else:
                    self._token(params, scope=None, credential=credential)
                    return Verification(host, "ok", "token issued")
        except _Rejected as exc:
            return Verification(host, "rejected", str(exc))
        except _Unverifiable as exc:
            return Verification(host, "unreachable", str(exc))
        if response.status_code == 200 or (
            response.status_code == 401 and credential is None
        ):
            return Verification(host, "ok", f"{api} answered {response.status_code}")
        if response.status_code in (401, 403):
            return Verification(
                host, "rejected", f"{api} answered {response.status_code}"
            )
        return Verification(
            host, "unreachable", f"{api} answered {response.status_code}"
        )

    def _remembered(self, host: str, repository: str) -> str | None:
        """The repository's bearer token, while it has time left to run."""
        with self._lock:
            remembered = self._tokens.get((host, repository))
            if remembered is None:
                return None
            token, stale_at = remembered
            if stale_at <= self._clock():
                del self._tokens[(host, repository)]
                return None
            return f"Bearer {token}"

    def _forget(self, host: str, repository: str) -> None:
        with self._lock:
            self._tokens.pop((host, repository), None)

    def _authorization(
        self, registry: RegistryConfig, credential: tuple[str, str] | None
    ) -> str | None:
        # ECR takes the credential itself, so there is no challenge to wait for.
        if registry.auth == "ecr" and credential is not None:
            return _basic(credential)
        return None

    def _authorize(
        self,
        response: httpx.Response,
        repository: str,
        credential: tuple[str, str] | None,
    ) -> str | None:
        challenge = _challenge(response)
        if challenge is None:
            return None
        scheme, params = challenge
        if scheme == "basic":
            return _basic(credential) if credential is not None else None
        token, lifetime = self._token(
            params, scope=f"repository:{repository}:pull", credential=credential
        )
        host = response.url.host
        with self._lock:
            if len(self._tokens) >= _MAX_TOKENS:
                self._tokens.clear()
            self._tokens[(host, repository)] = (
                token,
                self._clock() + lifetime - _TOKEN_REFRESH_MARGIN_SECONDS,
            )
        return f"Bearer {token}"

    def _token(
        self,
        params: Mapping[str, str],
        *,
        scope: str | None,
        credential: tuple[str, str] | None,
    ) -> tuple[str, float]:
        """A token, and the seconds it lasts."""
        realm = params.get("realm", "")
        if not realm.startswith("https://"):
            raise _Unverifiable(f"token realm {realm!r} is not https")
        query = {"service": params["service"]} if "service" in params else {}
        if scope is not None:
            query["scope"] = scope
        url = httpx.URL(realm, params=query)
        response = self._send(
            "GET", url, _basic(credential) if credential is not None else None
        )
        if response.status_code in (401, 403) and credential is not None:
            raise _Rejected(
                f"{url.host} refused the credential ({response.status_code})"
            )
        if response.status_code != 200:
            raise _Unverifiable(
                f"{url.host} answered {response.status_code} for a token"
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise _Unverifiable(f"{url.host} sent a token that is not JSON") from exc
        token = body.get("token") or body.get("access_token")
        if not isinstance(token, str) or not token:
            raise _Unverifiable(f"{url.host} sent no token")
        lifetime = body.get("expires_in")
        if not isinstance(lifetime, int | float) or lifetime <= 0:
            lifetime = _DEFAULT_TOKEN_LIFETIME_SECONDS
        return token, float(lifetime)

    def _send(
        self, method: str, url: httpx.URL, authorization: str | None
    ) -> httpx.Response:
        headers = {"Accept": MANIFEST_MEDIA_TYPES}
        if authorization is not None:
            headers["Authorization"] = authorization
        problem = ""
        delay = 0.0
        for attempt in range(self._attempts):
            if attempt:
                self._sleep(delay)
            # Exponential unless the registry says how long, and bounded either
            # way: a pull request waits on this.
            delay = min(_MAX_BACKOFF_SECONDS, 0.5 * 2 ** (attempt + 1))
            try:
                response = self._http.request(method, url, headers=headers)
            except httpx.HTTPError as exc:
                problem = f"{url.host}: {type(exc).__name__}: {exc}"
                continue
            if response.status_code not in _RETRY_STATUSES:
                return response
            problem = f"{url.host} answered {response.status_code}"
            retry_after = response.headers.get("retry-after", "")
            if retry_after.isdigit():
                delay = min(_MAX_BACKOFF_SECONDS, float(retry_after))
        raise _Unverifiable(f"{problem}, after {self._attempts} attempts")


def _challenge(response: httpx.Response) -> tuple[str, dict[str, str]] | None:
    match = _CHALLENGE.match(response.headers.get("www-authenticate", ""))
    if match is None:
        return None
    return match.group(1).lower(), dict(_CHALLENGE_PARAM.findall(match.group(2)))


def _basic(credential: tuple[str, str]) -> str:
    username, password = credential
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


class ExistenceCache:
    """Images found to exist, believed to for a while.

    Only existence is remembered. A missing image is asked about again every
    time, so pushing it is enough to clear the finding.
    """

    def __init__(
        self,
        ttl_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 4096,
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._max_entries = max_entries
        self._found: dict[str, float] = {}
        self._lock = threading.Lock()

    def __contains__(self, key: str) -> bool:
        with self._lock:
            expires = self._found.get(key)
            if expires is None:
                return False
            if expires <= self._clock():
                del self._found[key]
                return False
            return True

    def add(self, key: str) -> None:
        with self._lock:
            if len(self._found) >= self._max_entries:
                now = self._clock()
                self._found = {k: e for k, e in self._found.items() if e > now}
                if len(self._found) >= self._max_entries:
                    self._found.clear()
            self._found[key] = self._clock() + self._ttl


class RegistryLookup(Protocol):
    def lookup(self, image: ImageReference, registry: RegistryConfig) -> Lookup: ...

    def verify(self, registry: RegistryConfig) -> Verification: ...


class SharedLookups:
    """One request per image at a time, however many validations want it.

    relcoord validates a change's trees concurrently, and they mostly name the
    same images, so a bump would otherwise ask a registry the same question once
    per tree in flight, which is what trips its rate limit. A lookup already
    under way is waited for instead, whatever it answers.

    An image found to exist is added to the cache before the lookup stops being
    shared, so a validation arriving in between finds one or the other and
    never asks again.
    """

    def __init__(self, client: RegistryLookup, cache: ExistenceCache) -> None:
        self._client = client
        self._cache = cache
        self._in_flight: dict[str, Future[Lookup]] = {}
        self._lock = threading.Lock()

    def known(self, image: ImageReference) -> bool:
        return image.key in self._cache

    def lookup(self, image: ImageReference, registry: RegistryConfig) -> Lookup:
        key = image.key
        with self._lock:
            shared = self._in_flight.get(key)
            if shared is None:
                if key in self._cache:
                    return Lookup("found")
                mine: Future[Lookup] = Future()
                self._in_flight[key] = mine
        if shared is not None:
            return shared.result()
        try:
            result = self._client.lookup(image, registry)
            if result.outcome == "found":
                self._cache.add(key)
            mine.set_result(result)
            return result
        except BaseException as exc:
            mine.set_exception(exc)
            raise
        finally:
            with self._lock:
                del self._in_flight[key]


@dataclass(frozen=True)
class _Place:
    file: str
    resource: str


class ImageExistsChecker:
    """Every image a tree references exists in a declared registry."""

    cacheable = False
    version = "1"

    def __init__(
        self,
        registries: Sequence[RegistryConfig],
        client: RegistryLookup,
        cache: ExistenceCache,
        *,
        workers: int = 8,
    ) -> None:
        self._registries = {registry.host: registry for registry in registries}
        self._client = client
        self._lookups = SharedLookups(client, cache)
        self._workers = workers

    @property
    def name(self) -> str:
        return "image-exists"

    def verify_registries(self) -> list[Verification]:
        return [self._client.verify(r) for r in self._registries.values()]

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        places: dict[str, list[_Place]] = {}
        for path, index, document, parse_error in tree.documents:
            if parse_error is not None or not isinstance(document, dict):
                continue
            for text in image_references(document):
                places.setdefault(text, []).append(_Place(path, f"{path}#{index}"))
        progress("running", f"image-exists: {len(places)} images")

        problems: dict[str, tuple[str, Severity, str]] = {}
        # Keyed on the reference text, for the finding's wording, and asked by
        # target: two spellings of one image, or a mirror and its upstream, are
        # one question.
        pending: dict[str, tuple[ImageReference, RegistryConfig, RegistryConfig]] = {}
        for text in places:
            try:
                image = parse_reference(text)
            except ValueError as exc:
                problems[text] = (
                    "invalid-reference",
                    "high",
                    f"{text!r} is not an image reference a runtime can pull: {exc}",
                )
                continue
            declared = self._registries.get(image.registry)
            if declared is None:
                problems[text] = (
                    "unknown-registry",
                    "high",
                    f"image {text!r} is on {image.registry}, which this check has "
                    "no declaration for; declare it with its credential",
                )
                continue
            target, registry = self._target(image, declared)
            if not self._lookups.known(target):
                pending[text] = (target, registry, declared)

        targets = {
            target.key: (target, registry) for target, registry, _ in pending.values()
        }
        if targets:
            progress("running", f"image-exists: asking about {len(targets)} images")
            with ThreadPoolExecutor(
                max_workers=min(self._workers, len(targets)),
                thread_name_prefix="image-exists",
            ) as pool:
                lookups = dict(
                    zip(
                        targets,
                        pool.map(
                            lambda pair: self._lookups.lookup(*pair), targets.values()
                        ),
                        strict=True,
                    )
                )
            for text, (target, registry, declared) in pending.items():
                lookup = lookups[target.key]
                if lookup.outcome != "found":
                    problems[text] = _problem(text, target, registry, declared, lookup)

        findings = tuple(
            Finding(
                rule_id=f"image-exists/{rule}",
                severity=severity,
                message=message,
                file=place.file,
                resource=place.resource,
            )
            for text, (rule, severity, message) in problems.items()
            for place in places[text]
        )
        return Verdict(
            passed=not findings,
            tool=self.name,
            tool_version=self.version,
            ruleset_digest=ruleset_digest(
                self.name,
                self.version,
                *sorted(r.describe() for r in self._registries.values()),
            ),
            findings=findings,
        )

    def _target(
        self, image: ImageReference, declared: RegistryConfig
    ) -> tuple[ImageReference, RegistryConfig]:
        """Where to ask: the registry itself, or the upstream it mirrors."""
        if declared.mirror_of is None:
            return image, declared
        upstream = self._registries[declared.mirror_of]
        repository = image.repository
        if upstream.host == DOCKER_HUB and "/" not in repository:
            repository = f"library/{repository}"
        return replace(image, registry=upstream.host, repository=repository), upstream


def _problem(
    text: str,
    target: ImageReference,
    registry: RegistryConfig,
    declared: RegistryConfig,
    lookup: Lookup,
) -> tuple[str, Severity, str]:
    mirrored = (
        ""
        if declared is registry
        else f"; checked at {registry.host}, which {declared.host} mirrors"
    )
    if lookup.outcome == "missing":
        return (
            "missing",
            "critical",
            f"image {text!r} does not exist: {registry.host} has no {target.key} "
            f"({lookup.detail}{mirrored})",
        )
    if lookup.outcome == "denied":
        return (
            "denied",
            "high",
            f"image {text!r} does not exist, or the {registry.auth} credential for "
            f"{registry.host} cannot read it ({lookup.detail}{mirrored})",
        )
    return (
        "unverifiable",
        "high",
        f"could not tell whether image {text!r} exists in {registry.host}: "
        f"{lookup.detail}{mirrored}",
    )
