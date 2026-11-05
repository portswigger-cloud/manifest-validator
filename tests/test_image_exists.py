# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import base64
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from manifest_validator.config import RegistryConfig
from manifest_validator.errors import RegistryCredentialError, RegistryUnreachable
from manifest_validator.image_exists import (
    EcrToken,
    ExistenceCache,
    ImageExistsChecker,
    ImageReference,
    Lookup,
    RegistryClient,
    RegistryCredentials,
    Verification,
    parse_reference,
)
from manifest_validator.models import Tree

DIGEST = "sha256:" + "a" * 64
ECR_HOST = "123456789012.dkr.ecr.eu-west-1.amazonaws.com"

Handler = Callable[[httpx.Request], httpx.Response]


def _noop(phase: str, message: str) -> None:
    return None


def _no_sleep(seconds: float) -> None:
    return None


class FakeEcr:
    def __init__(self, expires_at: float = 10_000_000.0) -> None:
        self.calls = 0
        self.expires_at = expires_at

    def token(self, region: str) -> EcrToken:
        self.calls += 1
        return EcrToken("AWS", f"ecr-password-{self.calls}", self.expires_at)


class Recorder:
    """A registry served from a function, remembering what was asked of it."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


def _client(
    handler: Handler,
    ecr: FakeEcr | None = None,
    attempts: int = 3,
    clock: Callable[[], float] = lambda: 0.0,
) -> tuple[RegistryClient, Recorder]:
    recorder = Recorder(handler)
    client = RegistryClient(
        RegistryCredentials(ecr or FakeEcr(), clock=clock),
        http=httpx.Client(
            transport=httpx.MockTransport(recorder), follow_redirects=True
        ),
        attempts=attempts,
        sleep=_no_sleep,
    )
    return client, recorder


def _bearer_challenge(realm: str, service: str = "registry.example") -> dict[str, str]:
    return {"www-authenticate": f'Bearer realm="{realm}",service="{service}"'}


def _basic_header(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def _basic_registry(tmp_path: Path, host: str = "registry.example") -> RegistryConfig:
    (tmp_path / "username").write_text("robot\n")
    (tmp_path / "password").write_text("s3cret\n")
    return RegistryConfig(
        host=host,
        auth="basic",
        username_file=str(tmp_path / "username"),
        password_file=str(tmp_path / "password"),
    )


def _token_registry(manifests: dict[str, int], token_status: int = 200) -> Handler:
    """A registry with a bearer token flow, answering HEADs from `manifests`."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.example":
            if token_status != 200:
                return httpx.Response(token_status)
            return httpx.Response(200, json={"token": "t0k3n"})
        if request.headers.get("authorization") != "Bearer t0k3n":
            return httpx.Response(
                401, headers=_bearer_challenge("https://auth.example/token")
            )
        return httpx.Response(manifests.get(request.url.path, 404))

    return handler


# --- references ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "registry", "repository", "reference"),
    [
        ("redis", "docker.io", "library/redis", "latest"),
        ("docker:dind", "docker.io", "library/docker", "dind"),
        ("grafana/renderer:v5", "docker.io", "grafana/renderer", "v5"),
        ("docker.io/library/redis:8", "docker.io", "library/redis", "8"),
        (
            "registry-1.docker.io/portswigger/dhi-curl:8.14@" + DIGEST,
            "docker.io",
            "portswigger/dhi-curl",
            DIGEST,
        ),
        (
            "quay.io/prometheus/node-exporter:v1.9",
            "quay.io",
            "prometheus/node-exporter",
            "v1.9",
        ),
        ("localhost:5000/tools/x:1", "localhost:5000", "tools/x", "1"),
        (f"{ECR_HOST}/apps/runner:7623a0a", ECR_HOST, "apps/runner", "7623a0a"),
    ],
)
def test_references_resolve_as_a_runtime_resolves_them(
    text: str, registry: str, repository: str, reference: str
) -> None:
    image = parse_reference(text)
    assert (image.registry, image.repository, image.reference) == (
        registry,
        repository,
        reference,
    )


@pytest.mark.parametrize(
    "text",
    ["quay.io/Upper/case:1", "redis@sha256:short", "redis:bad tag", "quay.io/:1"],
)
def test_malformed_references_are_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        parse_reference(text)


# --- registry client ----------------------------------------------------------


def test_an_existing_image_is_found_through_an_anonymous_token() -> None:
    client, recorder = _client(_token_registry({"/v2/team/app/manifests/1.0": 200}))
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"),
        RegistryConfig("registry.example"),
    )
    assert lookup.outcome == "found"
    token_request = recorder.requests[1]
    assert token_request.url.params["scope"] == "repository:team/app:pull"
    assert "authorization" not in token_request.headers


def test_a_manifest_head_asks_for_every_manifest_type() -> None:
    client, recorder = _client(_token_registry({"/v2/team/app/manifests/1.0": 200}))
    client.lookup(
        parse_reference("registry.example/team/app:1.0"),
        RegistryConfig("registry.example"),
    )
    head = recorder.requests[-1]
    assert head.method == "HEAD"
    assert "application/vnd.oci.image.index.v1+json" in head.headers["accept"]


def test_a_404_is_missing() -> None:
    client, _ = _client(_token_registry({}))
    lookup = client.lookup(
        parse_reference("registry.example/team/app:nope"),
        RegistryConfig("registry.example"),
    )
    assert lookup.outcome == "missing"


def test_a_401_after_the_token_flow_is_denied() -> None:
    client, _ = _client(_token_registry({"/v2/team/app/manifests/1.0": 401}))
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"),
        RegistryConfig("registry.example"),
    )
    assert lookup.outcome == "denied"


def test_a_token_is_reused_for_the_same_repository() -> None:
    client, recorder = _client(
        _token_registry(
            {"/v2/team/app/manifests/1.0": 200, "/v2/team/app/manifests/2.0": 200}
        )
    )
    registry = RegistryConfig("registry.example")
    client.lookup(parse_reference("registry.example/team/app:1.0"), registry)
    client.lookup(parse_reference("registry.example/team/app:2.0"), registry)
    assert sum(r.url.host == "auth.example" for r in recorder.requests) == 1


def test_a_basic_credential_is_offered_to_the_token_endpoint(tmp_path: Path) -> None:
    client, recorder = _client(_token_registry({"/v2/team/app/manifests/1.0": 200}))
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"), _basic_registry(tmp_path)
    )
    assert lookup.outcome == "found"
    token_request = recorder.requests[1]
    assert token_request.headers["authorization"] == _basic_header("robot", "s3cret")


def test_a_refused_credential_is_denied_and_says_so(tmp_path: Path) -> None:
    client, _ = _client(_token_registry({}, token_status=401))
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"), _basic_registry(tmp_path)
    )
    assert lookup.outcome == "denied"
    assert "refused the credential" in lookup.detail


def test_a_credential_never_follows_a_redirect_to_another_host(
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "registry.example":
            return httpx.Response(
                307, headers={"location": "https://cdn.example" + request.url.path}
            )
        if request.url.host == "auth.cdn.example":
            return httpx.Response(200, json={"token": "cdn-token"})
        if request.headers.get("authorization") == "Bearer cdn-token":
            return httpx.Response(200)
        return httpx.Response(
            401,
            headers=_bearer_challenge("https://auth.cdn.example/token", "cdn"),
        )

    client, recorder = _client(handler)
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"), _basic_registry(tmp_path)
    )
    assert lookup.outcome == "found"
    assert {r.url.host for r in recorder.requests} == {
        "registry.example",
        "cdn.example",
        "auth.cdn.example",
    }
    credential = _basic_header("robot", "s3cret")
    assert all(r.headers.get("authorization") != credential for r in recorder.requests)


def test_a_token_realm_that_is_not_https_is_not_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, headers=_bearer_challenge("http://auth.example/token")
        )

    client, recorder = _client(handler)
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"),
        RegistryConfig("registry.example"),
    )
    assert lookup.outcome == "unverifiable"
    assert all(r.url.host == "registry.example" for r in recorder.requests)


def test_ecr_is_sent_its_token_without_waiting_for_a_challenge() -> None:
    expected = _basic_header("AWS", "ecr-password-1")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") == expected:
            return httpx.Response(200)
        return httpx.Response(401)

    client, recorder = _client(handler)
    lookup = client.lookup(
        parse_reference(f"{ECR_HOST}/apps/runner:1"),
        RegistryConfig(ECR_HOST, auth="ecr"),
    )
    assert lookup.outcome == "found"
    assert len(recorder.requests) == 1


def test_an_ecr_token_is_replaced_before_it_expires() -> None:
    now = [0.0]
    ecr = FakeEcr(expires_at=3600.0)
    client, _ = _client(lambda r: httpx.Response(200), ecr=ecr, clock=lambda: now[0])
    image = parse_reference(f"{ECR_HOST}/apps/runner:1")
    registry = RegistryConfig(ECR_HOST, auth="ecr")
    client.lookup(image, registry)
    client.lookup(image, registry)
    assert ecr.calls == 1
    now[0] = 2000.0
    client.lookup(image, registry)
    assert ecr.calls == 2


def test_throttling_is_retried() -> None:
    answers = iter([429, 200])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(next(answers), headers={"retry-after": "1"})

    client, _ = _client(handler)
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"),
        RegistryConfig("registry.example"),
    )
    assert lookup.outcome == "found"


def test_a_registry_that_keeps_failing_is_unverifiable() -> None:
    client, recorder = _client(lambda r: httpx.Response(503), attempts=3)
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"),
        RegistryConfig("registry.example"),
    )
    assert lookup.outcome == "unverifiable"
    assert "after 3 attempts" in lookup.detail
    assert len(recorder.requests) == 3


def test_a_timeout_is_unverifiable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("too slow", request=request)

    client, _ = _client(handler, attempts=2)
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"),
        RegistryConfig("registry.example"),
    )
    assert lookup.outcome == "unverifiable"


def test_a_missing_credential_file_makes_a_lookup_unverifiable(
    tmp_path: Path,
) -> None:
    client, recorder = _client(lambda r: httpx.Response(200))
    registry = RegistryConfig(
        "registry.example",
        auth="basic",
        username_file=str(tmp_path / "absent"),
        password_file=str(tmp_path / "absent"),
    )
    lookup = client.lookup(parse_reference("registry.example/team/app:1"), registry)
    assert lookup.outcome == "unverifiable"
    assert recorder.requests == []


def test_an_empty_credential_file_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "username").write_text("robot")
    (tmp_path / "password").write_text("\n")
    credentials = RegistryCredentials(FakeEcr())
    registry = RegistryConfig(
        "registry.example",
        auth="basic",
        username_file=str(tmp_path / "username"),
        password_file=str(tmp_path / "password"),
    )
    with pytest.raises(RegistryCredentialError, match="is empty"):
        credentials.basic(registry)


# --- start-up verification ----------------------------------------------------


def test_an_anonymous_registry_that_answers_verifies() -> None:
    client, _ = _client(
        lambda r: httpx.Response(401, headers=_bearer_challenge("https://a.example/t"))
    )
    assert client.verify(RegistryConfig("registry.example")).outcome == "ok"


def test_an_unreachable_registry_is_not_a_rejected_credential(
    tmp_path: Path,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    client, _ = _client(handler, attempts=1)
    assert client.verify(_basic_registry(tmp_path)).outcome == "unreachable"


def test_a_basic_credential_is_verified_at_its_token_endpoint(tmp_path: Path) -> None:
    client, recorder = _client(_token_registry({}))
    assert client.verify(_basic_registry(tmp_path)).outcome == "ok"
    token_request = recorder.requests[-1]
    assert token_request.url.host == "auth.example"
    assert token_request.headers["authorization"] == _basic_header("robot", "s3cret")


def test_a_refused_basic_credential_is_rejected(tmp_path: Path) -> None:
    client, _ = _client(_token_registry({}, token_status=401))
    assert client.verify(_basic_registry(tmp_path)).outcome == "rejected"


def test_a_missing_basic_credential_is_rejected(tmp_path: Path) -> None:
    client, recorder = _client(lambda r: httpx.Response(200))
    registry = RegistryConfig(
        "registry.example",
        auth="basic",
        username_file=str(tmp_path / "absent"),
        password_file=str(tmp_path / "absent"),
    )
    assert client.verify(registry).outcome == "rejected"
    assert recorder.requests == []


@pytest.mark.parametrize(("status", "outcome"), [(200, "ok"), (401, "rejected")])
def test_an_ecr_credential_is_verified_against_the_registry(
    status: int, outcome: str
) -> None:
    client, _ = _client(lambda r: httpx.Response(status))
    assert client.verify(RegistryConfig(ECR_HOST, auth="ecr")).outcome == outcome


def test_an_ecr_role_without_a_token_is_rejected() -> None:
    class NoToken:
        def token(self, region: str) -> EcrToken:
            raise RegistryCredentialError("AccessDenied")

    client = RegistryClient(
        RegistryCredentials(NoToken()),
        http=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
        sleep=_no_sleep,
    )
    assert client.verify(RegistryConfig(ECR_HOST, auth="ecr")).outcome == "rejected"


# --- the check ----------------------------------------------------------------


class FakeRegistries:
    """Answers lookups from a table, and remembers what it was asked."""

    def __init__(self, outcomes: dict[str, Lookup] | None = None) -> None:
        self.outcomes = outcomes or {}
        self.asked: list[tuple[str, str]] = []

    def lookup(self, image: ImageReference, registry: RegistryConfig) -> Lookup:
        self.asked.append((image.key, registry.host))
        return self.outcomes.get(image.key, Lookup("found"))

    def verify(self, registry: RegistryConfig) -> Verification:
        return Verification(registry.host, "ok", "")


def _deployment(*images: str) -> str:
    containers = "".join(
        f"        - name: c{i}\n          image: {image}\n"
        for i, image in enumerate(images)
    )
    return (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n"
        "spec:\n  template:\n    spec:\n      containers:\n" + containers
    )


def _tree(files: dict[str, str]) -> Tree:
    return Tree(files={path: body.encode() for path, body in files.items()})


REGISTRIES = (
    RegistryConfig("quay.io"),
    RegistryConfig("docker.io"),
    RegistryConfig("docker-external.devtools.example", mirror_of="docker.io"),
)


def _checker(
    registries: FakeRegistries, clock: Callable[[], float] = lambda: 0.0
) -> ImageExistsChecker:
    return ImageExistsChecker(
        REGISTRIES, registries, ExistenceCache(ttl_seconds=60, clock=clock)
    )


def test_a_tree_whose_images_exist_passes() -> None:
    registries = FakeRegistries()
    verdict = _checker(registries).run(
        DIGEST, _tree({"d.yaml": _deployment("quay.io/team/app:1", "redis:8")}), _noop
    )
    assert verdict.passed
    assert sorted(registries.asked) == [
        ("docker.io/library/redis:8", "docker.io"),
        ("quay.io/team/app:1", "quay.io"),
    ]


def test_a_missing_image_names_the_image_and_every_file_that_uses_it() -> None:
    registries = FakeRegistries({"quay.io/team/app:9": Lookup("missing", "404")})
    tree = _tree(
        {
            "a/deployment.yaml": _deployment("quay.io/team/app:9"),
            "b/deployment.yaml": _deployment("quay.io/team/app:9"),
        }
    )
    verdict = _checker(registries).run(DIGEST, tree, _noop)
    assert not verdict.passed
    assert [(f.rule_id, f.file) for f in verdict.findings] == [
        ("image-exists/missing", "a/deployment.yaml"),
        ("image-exists/missing", "b/deployment.yaml"),
    ]
    assert "quay.io/team/app:9" in verdict.findings[0].message
    assert registries.asked == [("quay.io/team/app:9", "quay.io")]


def test_an_undeclared_registry_is_a_finding_and_is_never_contacted() -> None:
    registries = FakeRegistries()
    verdict = _checker(registries).run(
        DIGEST, _tree({"d.yaml": _deployment("evil.example/x:1")}), _noop
    )
    assert [f.rule_id for f in verdict.findings] == ["image-exists/unknown-registry"]
    assert registries.asked == []


def test_an_invalid_reference_is_a_finding() -> None:
    verdict = _checker(FakeRegistries()).run(
        DIGEST, _tree({"d.yaml": _deployment("quay.io/Team/App:1")}), _noop
    )
    assert [f.rule_id for f in verdict.findings] == ["image-exists/invalid-reference"]


@pytest.mark.parametrize(
    ("outcome", "rule"),
    [("denied", "image-exists/denied"), ("unverifiable", "image-exists/unverifiable")],
)
def test_an_unanswered_lookup_fails_closed(outcome: str, rule: str) -> None:
    registries = FakeRegistries({"quay.io/team/app:1": Lookup(outcome, "x")})  # ty: ignore
    verdict = _checker(registries).run(
        DIGEST, _tree({"d.yaml": _deployment("quay.io/team/app:1")}), _noop
    )
    assert not verdict.passed
    assert verdict.findings[0].rule_id == rule


def test_a_mirror_is_checked_at_its_upstream() -> None:
    registries = FakeRegistries(
        {"docker.io/library/docker:dind": Lookup("missing", "404")}
    )
    verdict = _checker(registries).run(
        DIGEST,
        _tree(
            {
                "d.yaml": _deployment(
                    "docker-external.devtools.example/library/docker:dind"
                )
            }
        ),
        _noop,
    )
    assert registries.asked == [("docker.io/library/docker:dind", "docker.io")]
    assert (
        "which docker-external.devtools.example mirrors" in verdict.findings[0].message
    )


def test_an_image_found_to_exist_is_believed_until_the_ttl_runs_out() -> None:
    now = [0.0]
    registries = FakeRegistries()
    checker = _checker(registries, clock=lambda: now[0])
    tree = _tree({"d.yaml": _deployment("quay.io/team/app:1")})
    checker.run(DIGEST, tree, _noop)
    checker.run(DIGEST, tree, _noop)
    assert len(registries.asked) == 1
    now[0] = 61.0
    checker.run(DIGEST, tree, _noop)
    assert len(registries.asked) == 2


def test_a_missing_image_is_asked_about_again() -> None:
    registries = FakeRegistries({"quay.io/team/app:1": Lookup("missing", "404")})
    checker = _checker(registries)
    tree = _tree({"d.yaml": _deployment("quay.io/team/app:1")})
    checker.run(DIGEST, tree, _noop)
    registries.outcomes.clear()
    assert checker.run(DIGEST, tree, _noop).passed
    assert len(registries.asked) == 2


def test_the_verdict_is_not_cacheable() -> None:
    assert ImageExistsChecker.cacheable is False


def test_registries_are_verified_one_by_one() -> None:
    results = _checker(FakeRegistries()).verify_registries()
    assert [r.registry for r in results] == [r.host for r in REGISTRIES]


def test_retry_after_is_waited_for_once() -> None:
    answers = iter(
        [httpx.Response(429, headers={"retry-after": "4"}), httpx.Response(200)]
    )
    slept: list[float] = []
    client = RegistryClient(
        RegistryCredentials(FakeEcr()),
        http=httpx.Client(transport=httpx.MockTransport(lambda r: next(answers))),
        sleep=slept.append,
    )
    lookup = client.lookup(
        parse_reference("registry.example/team/app:1.0"),
        RegistryConfig("registry.example"),
    )
    assert lookup.outcome == "found"
    assert slept == [4.0]


def test_an_ecr_token_source_that_cannot_reach_aws_is_unreachable() -> None:
    class Offline:
        def token(self, region: str) -> EcrToken:
            raise RegistryUnreachable("no route to sts")

    client = RegistryClient(
        RegistryCredentials(Offline()),
        http=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
        sleep=_no_sleep,
    )
    registry = RegistryConfig(ECR_HOST, auth="ecr")
    assert client.verify(registry).outcome == "unreachable"
    image = parse_reference(f"{ECR_HOST}/apps/runner:1")
    assert client.lookup(image, registry).outcome == "unverifiable"
