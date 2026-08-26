# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

from pathlib import Path

from manifest_validator.appconfig import AppConfigChecker, ContainerOutcome
from manifest_validator.models import Tree

DIGEST = "sha256:" + "a" * 64
IMAGE = "public.ecr.aws/portswigger-platform/idcat:1.0"
ALLOWED = ("public.ecr.aws/",)


def _noop(phase: str, message: str) -> None:
    return None


class StubRunner:
    """Records what it was asked to run, and answers however the test says."""

    def __init__(self, exit_code: int = 0, output: str = "") -> None:
        self._exit_code = exit_code
        self._output = output
        self.calls: list[tuple[str, dict[str, str], str]] = []

    def run(
        self, image: str, config_dir: Path, mount_path: str, timeout_seconds: int
    ) -> ContainerOutcome:
        contents = {
            path.name: path.read_text() for path in sorted(config_dir.iterdir())
        }
        self.calls.append((image, contents, mount_path))
        return ContainerOutcome(exit_code=self._exit_code, output=self._output)


class ExplodingRunner:
    def run(
        self, image: str, config_dir: Path, mount_path: str, timeout_seconds: int
    ) -> ContainerOutcome:
        raise RuntimeError("crun: could not create user namespace")


def _configmap(
    annotations: str = "",
    name: str = "idcat-config",
    data: str = '  idcat.toml: |\n    bind-address = "0.0.0.0:8080"\n',
) -> str:
    return (
        "# Source: idcat\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        f"  name: {name}\n"
        "  namespace: idcat\n"
        f"{annotations}"
        "data:\n"
    ) + data


def _annotations(
    validate: str = "true",
    image: str | None = IMAGE,
    mount_path: str | None = "/config",
) -> str:
    prefix = "manifest-validator.portswigger.com"
    lines = [f"    {prefix}/validate-config: '{validate}'"]
    if image is not None:
        lines.append(f"    {prefix}/image: {image}")
    if mount_path is not None:
        lines.append(f"    {prefix}/mount-path: {mount_path}")
    return "  annotations:\n" + "\n".join(lines) + "\n"


def _tree(*documents: str, **files: str) -> Tree:
    contents = {f"configmap-{i}.yaml": doc for i, doc in enumerate(documents)}
    contents.update(files)
    return Tree(files={path: body.encode() for path, body in contents.items()})


def _checker(runner: object, **kwargs: object) -> AppConfigChecker:
    return AppConfigChecker(
        **(
            {
                "check_name": "config",
                "runner": runner,
                "allowed_registries": ALLOWED,
            }
            | kwargs
        )  # ty: ignore
    )


def test_a_tree_with_no_declaration_passes_without_running_anything() -> None:
    runner = StubRunner()
    verdict = _checker(runner).run(DIGEST, _tree(_configmap()), _noop)

    assert verdict.passed
    assert verdict.findings == ()
    assert runner.calls == []


def test_a_valid_config_passes_and_the_image_sees_the_configmap_data() -> None:
    runner = StubRunner(exit_code=0)
    tree = _tree(_configmap(_annotations()))

    verdict = _checker(runner).run(DIGEST, tree, _noop)

    assert verdict.passed
    assert verdict.findings == ()
    assert runner.calls == [
        (IMAGE, {"idcat.toml": 'bind-address = "0.0.0.0:8080"\n'}, "/config")
    ]


def test_a_non_zero_exit_fails_the_verdict_and_reports_what_the_image_said() -> None:
    runner = StubRunner(exit_code=1, output="at least one [[role]] is required")
    tree = _tree(_configmap(_annotations()))

    verdict = _checker(runner).run(DIGEST, tree, _noop)

    assert not verdict.passed
    (finding,) = verdict.findings
    assert finding.rule_id == "config/invalid"
    assert finding.severity == "high"
    assert "at least one [[role]] is required" in finding.message
    assert finding.file == "configmap-0.yaml"


def test_the_verdict_names_the_image_that_decided_it() -> None:
    verdict = _checker(StubRunner()).run(
        DIGEST, _tree(_configmap(_annotations())), _noop
    )

    assert verdict.tool_version == IMAGE


def test_an_image_outside_the_allowed_registries_is_not_run() -> None:
    runner = StubRunner()
    tree = _tree(_configmap(_annotations(image="docker.io/somebody/idcat:1.0")))

    verdict = _checker(runner).run(DIGEST, tree, _noop)

    assert not verdict.passed
    (finding,) = verdict.findings
    assert finding.rule_id == "config/image-not-allowed"
    assert runner.calls == []


def test_a_declaration_missing_its_image_is_a_finding_not_a_skip() -> None:
    runner = StubRunner()
    tree = _tree(_configmap(_annotations(image=None)))

    verdict = _checker(runner).run(DIGEST, tree, _noop)

    assert not verdict.passed
    (finding,) = verdict.findings
    assert finding.rule_id == "config/malformed-declaration"
    assert "image" in finding.message
    assert runner.calls == []


def test_a_declaration_missing_its_mount_path_is_a_finding() -> None:
    tree = _tree(_configmap(_annotations(mount_path=None)))

    verdict = _checker(StubRunner()).run(DIGEST, tree, _noop)

    (finding,) = verdict.findings
    assert finding.rule_id == "config/malformed-declaration"
    assert "mount-path" in finding.message


def test_validate_config_false_is_not_a_declaration() -> None:
    runner = StubRunner()
    tree = _tree(_configmap(_annotations(validate="false")))

    verdict = _checker(runner).run(DIGEST, tree, _noop)

    assert verdict.passed
    assert runner.calls == []


def test_a_runner_that_cannot_start_fails_closed_with_a_check_error() -> None:
    tree = _tree(_configmap(_annotations()))

    verdict = _checker(ExplodingRunner()).run(DIGEST, tree, _noop)

    assert not verdict.passed
    (finding,) = verdict.findings
    assert finding.rule_id == "config/check-error"
    assert finding.severity == "critical"
    assert "user namespace" in finding.message


def test_every_declaration_in_a_tree_is_checked() -> None:
    runner = StubRunner()
    tree = _tree(
        _configmap(_annotations()),
        _configmap(
            _annotations(mount_path="/certs"),
            name="idcat-certs",
            data="  ca.pem: |\n    -----BEGIN CERTIFICATE-----\n",
        ),
    )

    _checker(runner).run(DIGEST, tree, _noop)

    assert [call[2] for call in runner.calls] == ["/config", "/certs"]


def test_output_is_truncated_so_one_finding_cannot_flood_a_pull_request() -> None:
    runner = StubRunner(exit_code=1, output="x" * 10_000)
    tree = _tree(_configmap(_annotations()))

    verdict = _checker(runner).run(DIGEST, tree, _noop)

    (finding,) = verdict.findings
    assert len(finding.message) < 5_000
    assert "truncated" in finding.message


def test_the_ruleset_digest_covers_the_registries_that_may_be_run() -> None:
    tree = _tree(_configmap(_annotations()))
    one = _checker(StubRunner(), allowed_registries=("public.ecr.aws/",))
    other = _checker(StubRunner(), allowed_registries=("public.ecr.aws/", "ghcr.io/"))

    assert (
        one.run(DIGEST, tree, _noop).ruleset_digest
        != other.run(DIGEST, tree, _noop).ruleset_digest
    )
