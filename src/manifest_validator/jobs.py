# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from manifest_validator.checks import ProgressSink
from manifest_validator.errors import CheckTimeout
from manifest_validator.models import Finding, Severity, Tree, Verdict

logger = logging.getLogger(__name__)

TREE_MOUNT = "/tree"
TOKEN_MOUNT = "/var/run/validator"
TOKEN_PATH = f"{TOKEN_MOUNT}/token"


@dataclass(frozen=True)
class JobSpec:
    name: str
    image: str
    args: tuple[str, ...]
    tree_url: str
    timeout_seconds: int
    fetcher_image: str
    token_audience: str
    service_account: str | None = None
    allow_egress: bool = False
    env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class JobOutcome:
    exit_code: int
    logs: str


class JobRunner(Protocol):
    def run(self, spec: JobSpec, progress: ProgressSink) -> JobOutcome: ...


class KubernetesJobRunner:
    """Creates one Job per check and blocks until it finishes.

    The Job pulls the tree from this service over HTTP; nothing is pushed into
    it, and no volume is shared.
    """

    def __init__(
        self,
        namespace: str,
        *,
        batch_api: Any,
        core_api: Any,
        poll_interval_seconds: float = 2.0,
    ) -> None:
        self._namespace = namespace
        self._batch = batch_api
        self._core = core_api
        self._poll_interval = poll_interval_seconds

    def run(self, spec: JobSpec, progress: ProgressSink) -> JobOutcome:
        body = self._manifest(spec)
        progress("scheduling", f"{spec.name}: creating Job")
        self._batch.create_namespaced_job(namespace=self._namespace, body=body)
        try:
            pod_name = self._await_completion(spec, progress)
            logs = self._core.read_namespaced_pod_log(
                name=pod_name, namespace=self._namespace
            )
            exit_code = self._exit_code(pod_name)
            return JobOutcome(exit_code=exit_code, logs=logs)
        finally:
            self._delete(spec.name)

    def _manifest(self, spec: JobSpec) -> dict[str, Any]:
        env = [{"name": key, "value": value} for key, value in sorted(spec.env.items())]
        env.append({"name": "TREE_URL", "value": spec.tree_url})
        pod_spec: dict[str, Any] = {
            "restartPolicy": "Never",
            "automountServiceAccountToken": spec.service_account is not None,
            "securityContext": {
                "runAsNonRoot": True,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "initContainers": [self._fetch_container(spec)],
            "containers": [
                {
                    "name": "check",
                    "image": spec.image,
                    "imagePullPolicy": "IfNotPresent",
                    "args": list(spec.args),
                    "env": env,
                    "volumeMounts": [{"name": "tree", "mountPath": TREE_MOUNT}],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }
            ],
            "volumes": [
                {"name": "tree", "emptyDir": {}},
                {
                    "name": "validator-token",
                    "projected": {
                        "sources": [
                            {
                                "serviceAccountToken": {
                                    "path": "token",
                                    "audience": spec.token_audience,
                                    "expirationSeconds": 3600,
                                }
                            }
                        ]
                    },
                },
            ],
        }
        if spec.service_account is not None:
            pod_spec["serviceAccountName"] = spec.service_account
        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": spec.name,
                "labels": {
                    "app.kubernetes.io/managed-by": "manifest-validator",
                    "manifest-validator.portswigger.io/egress": str(
                        spec.allow_egress
                    ).lower(),
                },
            },
            "spec": {
                "backoffLimit": 0,
                "activeDeadlineSeconds": spec.timeout_seconds,
                "ttlSecondsAfterFinished": 300,
                "template": {
                    "metadata": {
                        "labels": {
                            "app.kubernetes.io/managed-by": "manifest-validator",
                            "manifest-validator.portswigger.io/egress": str(
                                spec.allow_egress
                            ).lower(),
                        }
                    },
                    "spec": pod_spec,
                },
            },
        }

    def _fetch_container(self, spec: JobSpec) -> dict[str, Any]:
        """Pull and unpack the tree before the tool container starts.

        The fetch runs with the Job's own projected token, so each check
        authenticates to the tree endpoint as itself rather than sharing a
        secret with the other checks.
        """
        script = (
            "set -eu; "
            f'curl --fail --silent --show-error -H "Authorization: Bearer $(cat {TOKEN_PATH})" '
            f'"$TREE_URL" | tar -x -C {TREE_MOUNT}'
        )
        return {
            "name": "fetch-tree",
            "image": spec.fetcher_image,
            "imagePullPolicy": "IfNotPresent",
            "command": ["/bin/sh", "-c", script],
            "env": [{"name": "TREE_URL", "value": spec.tree_url}],
            "volumeMounts": [
                {"name": "tree", "mountPath": TREE_MOUNT},
                {
                    "name": "validator-token",
                    "mountPath": TOKEN_MOUNT,
                    "readOnly": True,
                },
            ],
            "securityContext": {
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            },
        }

    def _await_completion(self, spec: JobSpec, progress: ProgressSink) -> str:
        deadline = time.monotonic() + spec.timeout_seconds
        while time.monotonic() < deadline:
            pods = self._core.list_namespaced_pod(
                namespace=self._namespace, label_selector=f"job-name={spec.name}"
            )
            for pod in pods.items:
                phase = pod.status.phase
                if phase in ("Succeeded", "Failed"):
                    return pod.metadata.name
                progress("running", f"{spec.name}: pod {phase}")
            time.sleep(self._poll_interval)
        raise CheckTimeout(f"{spec.name} did not finish in {spec.timeout_seconds}s")

    def _exit_code(self, pod_name: str) -> int:
        pod = self._core.read_namespaced_pod(name=pod_name, namespace=self._namespace)
        for status in pod.status.container_statuses or []:
            terminated = status.state.terminated
            if terminated is not None:
                return int(terminated.exit_code)
        return 1

    def _delete(self, name: str) -> None:
        try:
            self._batch.delete_namespaced_job(
                name=name, namespace=self._namespace, propagation_policy="Background"
            )
        except Exception:
            logger.warning("could not delete Job %s", name, exc_info=True)


@dataclass(frozen=True)
class JobChecker:
    """A check that runs a tool in its own Job, with its own privileges."""

    check_name: str
    image: str
    args: tuple[str, ...]
    runner: JobRunner
    tree_url_template: str
    ruleset_digest: str
    tool_version: str
    fetcher_image: str = "public.ecr.aws/docker/library/alpine:3.22"
    token_audience: str = "manifest-validator"
    timeout_seconds: int = 600
    service_account: str | None = None
    allow_egress: bool = False
    env: dict[str, str] = field(default_factory=dict)
    findings_format: str = "exit-code"

    @property
    def name(self) -> str:
        return self.check_name

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        """`tree` is unused: the Job pulls the bytes itself, keyed on `digest`."""
        spec = JobSpec(
            name=_job_name(self.check_name, digest),
            image=self.image,
            args=self.args,
            tree_url=self.tree_url_template.format(digest=digest),
            timeout_seconds=self.timeout_seconds,
            fetcher_image=self.fetcher_image,
            token_audience=self.token_audience,
            service_account=self.service_account,
            allow_egress=self.allow_egress,
            env=dict(self.env),
        )
        outcome = self.runner.run(spec, progress)
        findings = _parse_findings(self.findings_format, outcome, self.check_name)
        return Verdict(
            passed=outcome.exit_code == 0 and not findings,
            tool=self.check_name,
            tool_version=self.tool_version,
            ruleset_digest=self.ruleset_digest,
            findings=findings,
        )


def _job_name(check_name: str, digest: str) -> str:
    short = digest.removeprefix("sha256:")[:12]
    return f"check-{check_name}-{short}"[:63].rstrip("-")


def _parse_findings(
    findings_format: str, outcome: JobOutcome, check_name: str
) -> tuple[Finding, ...]:
    if findings_format == "kics":
        return _parse_kics(outcome.logs)
    if outcome.exit_code == 0:
        return ()
    return (
        Finding(
            rule_id=f"{check_name}/non-zero-exit",
            severity="critical",
            message=f"exited {outcome.exit_code}: {outcome.logs.strip()[-2000:]}",
        ),
    )


def _parse_kics(logs: str) -> tuple[Finding, ...]:
    payload = _last_json_object(logs)
    if payload is None:
        return (
            Finding(
                rule_id="kics/unparseable-output",
                severity="critical",
                message="could not find a JSON report in the Job's output",
            ),
        )
    findings: list[Finding] = []
    for query in payload.get("queries", []):
        severity = str(query.get("severity", "info")).lower()
        for location in query.get("files", []):
            findings.append(
                Finding(
                    rule_id=str(query.get("query_id", "kics/unknown")),
                    severity=_severity(severity),
                    message=str(query.get("description", query.get("query_name", ""))),
                    file=location.get("file_name"),
                    resource=location.get("resource_name"),
                )
            )
    return tuple(findings)


def _last_json_object(logs: str) -> dict[str, Any] | None:
    for line in reversed(logs.splitlines()):
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def _severity(value: str) -> Severity:
    if value in ("critical", "high", "medium", "low", "info"):
        return value
    if value == "trace":
        return "info"
    return "info"
