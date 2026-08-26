# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import hashlib
import logging
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import yaml

from manifest_validator.checks import MANIFEST_SUFFIXES, ProgressSink
from manifest_validator.models import Finding, Tree, Verdict

logger = logging.getLogger(__name__)

# What manifest-builder stamps on a ConfigMap whose owning application can check
# its own config. The tree names an image and a path; the argv below is ours, so
# a generated tree cannot choose what runs.
ANNOTATION_PREFIX = "manifest-validator.portswigger.com"
VALIDATE_ANNOTATION = f"{ANNOTATION_PREFIX}/validate-config"
IMAGE_ANNOTATION = f"{ANNOTATION_PREFIX}/image"
MOUNT_PATH_ANNOTATION = f"{ANNOTATION_PREFIX}/mount-path"

VALIDATE_ARGV = ("--validate-config",)

# Enough of a diagnostic to act on, and not so much that one broken config
# buries the rest of a verdict in a pull request comment.
MAX_OUTPUT_CHARS = 4000


@dataclass(frozen=True)
class ContainerOutcome:
    exit_code: int
    output: str


class ContainerRunner(Protocol):
    """Runs one image over one directory of config, and says how it exited."""

    def run(
        self, image: str, config_dir: Path, mount_path: str, timeout_seconds: int
    ) -> ContainerOutcome: ...


@dataclass(frozen=True)
class Declaration:
    """One ConfigMap that says its own application can validate it."""

    file: str
    resource: str
    image: str
    mount_path: str
    data: Mapping[str, str]


@dataclass(frozen=True)
class AppConfigChecker:
    """Asks each application whether the config a tree holds for it is valid.

    No rule here knows what any application's config means, which is the point:
    the only thing that can decide is the application, so this runs it. What the
    tree supplies is an image and a mount path — never a command line.
    """

    check_name: str
    runner: ContainerRunner
    allowed_registries: tuple[str, ...] = ()
    timeout_seconds: int = 120
    version: str = "1"

    @property
    def name(self) -> str:
        return self.check_name

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        declarations, malformed = _declarations(tree)
        progress(
            "running",
            f"{self.check_name}: {len(declarations)} declared, {len(malformed)} malformed",
        )
        findings = list(malformed)
        for declaration in declarations:
            findings.extend(self._check(declaration, progress))
        return Verdict(
            passed=not findings,
            tool=self.check_name,
            tool_version=_images(declarations),
            ruleset_digest=self._ruleset_digest(),
            findings=tuple(findings),
        )

    def _check(
        self, declaration: Declaration, progress: ProgressSink
    ) -> Iterator[Finding]:
        if not self._may_run(declaration.image):
            yield Finding(
                rule_id=f"{self.check_name}/image-not-allowed",
                severity="high",
                message=(
                    f"{declaration.image!r} is not in an allowed registry, so it "
                    "was not run"
                ),
                file=declaration.file,
                resource=declaration.resource,
            )
            return
        progress("running", f"{self.check_name}: {declaration.image}")
        try:
            outcome = self._run_image(declaration)
        except Exception as exc:
            logger.exception("could not run %s", declaration.image)
            yield Finding(
                rule_id=f"{self.check_name}/check-error",
                severity="critical",
                message=f"could not run {declaration.image}: {exc}",
                file=declaration.file,
                resource=declaration.resource,
            )
            return
        if outcome.exit_code != 0:
            yield Finding(
                rule_id=f"{self.check_name}/invalid",
                severity="high",
                message=(
                    f"{declaration.image} rejected this config "
                    f"(exit {outcome.exit_code}): {_truncate(outcome.output)}"
                ),
                file=declaration.file,
                resource=declaration.resource,
            )

    def _run_image(self, declaration: Declaration) -> ContainerOutcome:
        with tempfile.TemporaryDirectory(prefix="manifest-validator-") as workspace:
            config_dir = Path(workspace) / "config"
            config_dir.mkdir()
            for key, content in declaration.data.items():
                _write_key(config_dir, key, content)
            return self.runner.run(
                declaration.image,
                config_dir,
                declaration.mount_path,
                self.timeout_seconds,
            )

    def _may_run(self, image: str) -> bool:
        return any(image.startswith(registry) for registry in self.allowed_registries)

    def _ruleset_digest(self) -> str:
        digest = hashlib.sha256()
        for part in (
            self.check_name,
            self.version,
            *VALIDATE_ARGV,
            *sorted(self.allowed_registries),
        ):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x00")
        return f"sha256:{digest.hexdigest()}"


def _write_key(config_dir: Path, key: str, content: str) -> None:
    """A ConfigMap key is a file name, and this one comes from the tree."""
    target = (config_dir / key).resolve()
    if target.parent != config_dir.resolve():
        raise ValueError(f"ConfigMap key {key!r} is not a plain file name")
    target.write_text(content)


def _declarations(tree: Tree) -> tuple[tuple[Declaration, ...], tuple[Finding, ...]]:
    """Every ConfigMap that opted in, and a finding for every one that opted in badly.

    A half-written declaration is reported rather than skipped: silence here
    would be indistinguishable from an application with no config to check.
    """
    declarations: list[Declaration] = []
    malformed: list[Finding] = []
    for path in sorted(tree.files):
        if not path.endswith(MANIFEST_SUFFIXES):
            continue
        try:
            documents = list(yaml.safe_load_all(tree.files[path]))
        except yaml.YAMLError:
            continue  # structural reports this; two findings for one cause is noise
        for index, document in enumerate(documents):
            annotations = _opted_in(document)
            if annotations is None:
                continue
            resource = _resource(document, path, index)
            image = annotations.get(IMAGE_ANNOTATION)
            mount_path = annotations.get(MOUNT_PATH_ANNOTATION)
            missing = [
                name
                for name, value in (
                    ("image", image),
                    ("mount-path", mount_path),
                )
                if not isinstance(value, str) or not value.strip()
            ]
            if missing:
                malformed.append(
                    Finding(
                        rule_id="config/malformed-declaration",
                        severity="high",
                        message=(
                            f"{VALIDATE_ANNOTATION} is set but "
                            f"{', '.join(missing)} is missing, so nothing could be run"
                        ),
                        file=path,
                        resource=resource,
                    )
                )
                continue
            assert isinstance(image, str) and isinstance(mount_path, str)
            data = document.get("data")
            declarations.append(
                Declaration(
                    file=path,
                    resource=resource,
                    image=image,
                    mount_path=mount_path,
                    data=data if isinstance(data, dict) else {},
                )
            )
    return tuple(declarations), tuple(malformed)


def _opted_in(document: Any) -> Mapping[str, Any] | None:
    if not isinstance(document, dict) or document.get("kind") != "ConfigMap":
        return None
    metadata = document.get("metadata")
    annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
    if not isinstance(annotations, dict):
        return None
    if str(annotations.get(VALIDATE_ANNOTATION, "")).lower() != "true":
        return None
    return annotations


def _resource(document: Mapping[str, Any], path: str, index: int) -> str:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        return f"{path}#{index}"
    namespace = metadata.get("namespace")
    name = metadata.get("name")
    if isinstance(namespace, str) and isinstance(name, str):
        return f"{namespace}/{name}"
    return str(name) if isinstance(name, str) else f"{path}#{index}"


def _images(declarations: tuple[Declaration, ...]) -> str:
    """What actually decided this verdict, so a disagreement is explainable."""
    images = sorted({declaration.image for declaration in declarations})
    return ", ".join(images) if images else "nothing-declared"


def _truncate(output: str) -> str:
    text = output.strip()
    if len(text) <= MAX_OUTPUT_CHARS:
        return text or "(no output)"
    return f"{text[:MAX_OUTPUT_CHARS]}… (truncated)"


def _mount_target(mount_path: str) -> PurePosixPath:
    return PurePosixPath(mount_path)
