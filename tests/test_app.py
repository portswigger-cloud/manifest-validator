# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import io
import json
import tarfile
from typing import Any

import pytest
from starlette.testclient import TestClient

from manifest_validator.app import create_app
from manifest_validator.checks import ProgressSink, StructuralChecker
from manifest_validator.models import Tree, Verdict
from manifest_validator.service import ValidationService
from manifest_validator.trees import InMemoryTreeStore, compute_digest

GOOD = b"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: a\n"
BAD = b"kind: Namespace\n"


@pytest.fixture
def store() -> InMemoryTreeStore:
    return InMemoryTreeStore()


@pytest.fixture
def client(store: InMemoryTreeStore) -> TestClient:
    service = ValidationService({"structural": StructuralChecker()}, store)
    return TestClient(create_app(service, store, None))


def _blob(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, content in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _params(
    files: dict[str, bytes], digest: str | None, checks: list[str] | None
) -> list[tuple[str, Any]]:
    params: list[tuple[str, Any]] = [
        ("digest", digest if digest is not None else compute_digest(files))
    ]
    return params + [("check", check) for check in (checks or [])]


def _post(
    client: TestClient,
    files: dict[str, bytes],
    *,
    digest: str | None = None,
    checks: list[str] | None = None,
    body: bytes | None = None,
) -> Any:
    return client.post(
        "/v1/validate",
        content=_blob(files) if body is None else body,
        params=_params(files, digest, checks),
        headers={"content-type": "application/gzip"},
    )


def test_healthz(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_validate_returns_a_green_verdict(client: TestClient) -> None:
    response = _post(client, {"a.yaml": GOOD})
    assert response.status_code == 200
    payload = response.json()
    assert payload["passed"] is True
    assert payload["verdicts"][0]["tool"] == "structural"
    assert payload["verdicts"][0]["ruleset_digest"].startswith("sha256:")


def test_validate_returns_findings_on_a_red_verdict(client: TestClient) -> None:
    payload = _post(client, {"a.yaml": BAD}).json()
    assert payload["passed"] is False
    rule_ids = {f["rule_id"] for f in payload["verdicts"][0]["findings"]}
    assert "structural/missing-apiversion" in rule_ids


def test_the_digest_is_of_the_content_not_the_blob(client: TestClient) -> None:
    """Two separately built blobs of one tree share a digest."""
    files = {"a.yaml": GOOD}
    for body in (_blob(files), _blob({"a.yaml": GOOD})):
        response = _post(client, files, body=body)
        assert response.status_code == 200
        assert response.json()["digest"] == compute_digest(files)


def test_validate_rejects_a_digest_mismatch(client: TestClient) -> None:
    response = _post(client, {"a.yaml": GOOD}, digest="sha256:" + "0" * 64)
    assert response.status_code == 400
    assert "digest mismatch" in response.json()["error"]


def test_validate_requires_a_digest(client: TestClient) -> None:
    response = client.post(
        "/v1/validate",
        content=_blob({"a.yaml": GOOD}),
        headers={"content-type": "application/gzip"},
    )
    assert response.status_code == 400
    assert "digest" in response.json()["error"]


def test_validate_rejects_an_unknown_check(client: TestClient) -> None:
    response = _post(client, {"a.yaml": GOOD}, checks=["kics"])
    assert response.status_code == 400
    assert "unknown check" in response.json()["error"]


def test_validate_rejects_a_body_that_is_not_a_gzipped_tar(client: TestClient) -> None:
    response = _post(client, {"a.yaml": GOOD}, body=b"not a gzip at all")
    assert response.status_code == 400
    assert "gzipped tar" in response.json()["error"]


def test_validate_rejects_an_empty_archive(client: TestClient) -> None:
    response = _post(client, {"a.yaml": GOOD}, body=_blob({}))
    assert response.status_code == 400
    assert "no files" in response.json()["error"]


def test_validate_rejects_a_traversing_member(client: TestClient) -> None:
    response = _post(client, {"a.yaml": GOOD}, body=_blob({"../escape.yaml": GOOD}))
    assert response.status_code == 400
    assert "relative" in response.json()["error"]


def test_validate_streams_progress_then_a_result(client: TestClient) -> None:
    files = {"a.yaml": GOOD}
    with client.stream(
        "POST",
        "/v1/validate",
        content=_blob(files),
        params=_params(files, None, None),
        headers={"accept": "text/event-stream", "content-type": "application/gzip"},
    ) as response:
        assert response.status_code == 200
        events = _parse_sse("".join(response.iter_text()))
    names = [name for name, _ in events]
    assert names[-1] == "result"
    assert "validated" in names
    assert json.loads(events[-1][1])["passed"] is True


def test_stream_reports_a_digest_mismatch_as_an_error_event(client: TestClient) -> None:
    files = {"a.yaml": GOOD}
    with client.stream(
        "POST",
        "/v1/validate",
        content=_blob(files),
        params=_params(files, "sha256:" + "0" * 64, None),
        headers={"accept": "text/event-stream", "content-type": "application/gzip"},
    ) as response:
        events = _parse_sse("".join(response.iter_text()))
    assert events[-1][0] == "error"


def test_tree_endpoint_serves_a_tar(store: InMemoryTreeStore) -> None:
    service = ValidationService({"structural": StructuralChecker()}, store)
    client = TestClient(create_app(service, store, None))
    store.put("sha256:abc", Tree(files={"a.yaml": GOOD}))
    response = client.get("/v1/trees/sha256:abc")
    assert response.status_code == 200
    with tarfile.open(fileobj=io.BytesIO(response.content)) as archive:
        assert archive.getnames() == ["a.yaml"]


def test_tree_endpoint_404s_for_an_unknown_digest(client: TestClient) -> None:
    assert client.get("/v1/trees/sha256:nope").status_code == 404


def test_a_job_can_pull_the_tree_while_its_check_runs(store: InMemoryTreeStore) -> None:
    """The Job pulls over HTTP, so the tree must be reachable mid-check."""
    pulled: list[list[str]] = []

    class PullingChecker:
        @property
        def name(self) -> str:
            return "puller"

        def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
            response = client.get(f"/v1/trees/{digest}")
            with tarfile.open(fileobj=io.BytesIO(response.content)) as archive:
                pulled.append(archive.getnames())
            return Verdict(True, "puller", "1", "sha256:x")

    service = ValidationService({"puller": PullingChecker()}, store)
    client = TestClient(create_app(service, store, None))
    assert _post(client, {"a.yaml": GOOD}).json()["passed"]
    assert pulled == [["a.yaml"]]


def _parse_sse(raw: str) -> list[tuple[str, str]]:
    events: list[tuple[str, str]] = []
    for block in raw.strip().split("\n\n"):
        name = data = ""
        for line in block.splitlines():
            if line.startswith("event: "):
                name = line.removeprefix("event: ")
            elif line.startswith("data: "):
                data = line.removeprefix("data: ")
        if name:
            events.append((name, data))
    return events
