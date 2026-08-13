# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import json
import pathlib
import tomllib

from manifest_validator.jobs import (
    JobChecker,
    JobOutcome,
    JobSpec,
    KubernetesJobRunner,
)
from manifest_validator.models import Tree

DIGEST = "sha256:" + "a" * 64
TREE = Tree(files={"a.yaml": b"apiVersion: v1\n"})


def _noop(phase: str, message: str) -> None:
    return None


class StubRunner:
    def __init__(self, outcome: JobOutcome) -> None:
        self._outcome = outcome
        self.specs: list[JobSpec] = []

    def run(self, spec: JobSpec, progress: object) -> JobOutcome:
        self.specs.append(spec)
        return self._outcome


def _spec() -> JobSpec:
    return JobSpec(
        name="check-kics-abc",
        image="ghcr.io/portswigger-cloud/checkmarx/kics:v2.1.16",
        args=("scan",),
        tree_url="http://validator:8080/v1/trees/sha256:abc",
        timeout_seconds=600,
        fetcher_image="public.ecr.aws/docker/library/alpine:3.22",
        token_audience="manifest-validator",
    )


def _checker(runner: StubRunner, **kwargs: object) -> JobChecker:
    defaults: dict[str, object] = {
        "check_name": "kics",
        "image": "docker.io/checkmarx/kics:v2.1.16",
        "args": ("scan", "-p", "/tree"),
        "runner": runner,
        "tree_url_template": "http://validator:8080/v1/trees/{digest}",
        "ruleset_digest": "sha256:rules",
        "tool_version": "v2.1.16",
    }
    return JobChecker(**(defaults | kwargs))  # ty: ignore


def test_the_job_is_told_where_to_pull_the_tree() -> None:
    runner = StubRunner(JobOutcome(exit_code=0, logs=""))
    _checker(runner).run(DIGEST, TREE, _noop)
    assert runner.specs[0].tree_url == f"http://validator:8080/v1/trees/{DIGEST}"


def test_the_job_name_is_a_valid_kubernetes_name() -> None:
    runner = StubRunner(JobOutcome(exit_code=0, logs=""))
    _checker(runner).run(DIGEST, TREE, _noop)
    name = runner.specs[0].name
    assert len(name) <= 63
    assert name == "check-kics-aaaaaaaaaaaa"


def test_a_clean_exit_passes() -> None:
    runner = StubRunner(JobOutcome(exit_code=0, logs=""))
    verdict = _checker(runner).run(DIGEST, TREE, _noop)
    assert verdict.passed
    assert verdict.tool_version == "v2.1.16"
    assert verdict.ruleset_digest == "sha256:rules"


def test_a_non_zero_exit_fails_with_the_tail_of_the_log() -> None:
    runner = StubRunner(JobOutcome(exit_code=50, logs="boom happened"))
    verdict = _checker(runner).run(DIGEST, TREE, _noop)
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "kics/non-zero-exit"
    assert "boom happened" in verdict.findings[0].message


def test_kics_json_findings_are_parsed() -> None:
    report = {
        "queries": [
            {
                "query_id": "abc-123",
                "query_name": "Seccomp Profile Is Not Configured",
                "severity": "HIGH",
                "description": "Seccomp is unset",
                "files": [
                    {"file_name": "platform-dev/a.yaml", "resource_name": "relcoord"}
                ],
            }
        ]
    }
    logs = "scanning...\n" + json.dumps(report)
    runner = StubRunner(JobOutcome(exit_code=50, logs=logs))
    verdict = _checker(runner, findings_format="kics").run(DIGEST, TREE, _noop)
    assert not verdict.passed
    finding = verdict.findings[0]
    assert finding.rule_id == "abc-123"
    assert finding.severity == "high"
    assert finding.file == "platform-dev/a.yaml"
    assert finding.resource == "relcoord"


def test_kics_with_no_findings_passes() -> None:
    logs = json.dumps({"queries": []})
    runner = StubRunner(JobOutcome(exit_code=0, logs=logs))
    assert _checker(runner, findings_format="kics").run(DIGEST, TREE, _noop).passed


def test_unparseable_kics_output_fails_rather_than_passing_silently() -> None:
    """A green verdict that checked nothing is the failure mode to avoid."""
    runner = StubRunner(JobOutcome(exit_code=0, logs="segfault"))
    verdict = _checker(runner, findings_format="kics").run(DIGEST, TREE, _noop)
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "kics/unparseable-output"


def test_egress_is_denied_by_default() -> None:
    runner = StubRunner(JobOutcome(exit_code=0, logs=""))
    _checker(runner).run(DIGEST, TREE, _noop)
    assert runner.specs[0].allow_egress is False
    assert runner.specs[0].service_account is None


def test_images_are_reused_from_the_node_cache() -> None:
    """Always would re-pull on every validation, and pulls are the slow part."""
    runner = StubRunner(JobOutcome(exit_code=0, logs=""))
    manifest = KubernetesJobRunner(
        "manifest-validator", batch_api=None, core_api=None
    )._manifest(_spec())
    pod = manifest["spec"]["template"]["spec"]
    policies = [c["imagePullPolicy"] for c in pod["initContainers"] + pod["containers"]]
    assert policies == ["IfNotPresent", "IfNotPresent"]
    assert runner.specs == []


def test_no_check_image_comes_from_docker_hub() -> None:
    """docker.io is rate-limited per source IP and the cluster shares one NAT."""
    example = (
        pathlib.Path(__file__).resolve().parents[1] / "manifest-validator.toml.example"
    )
    with example.open("rb") as handle:
        data = tomllib.load(handle)
    images = [c["image"] for c in data["check"] if "image" in c]
    images.append(data["jobs"]["fetcher-image"])
    assert images
    for image in images:
        assert not image.startswith("docker.io/"), image
        assert "/" in image.split(":")[0], f"{image} has no registry host"
