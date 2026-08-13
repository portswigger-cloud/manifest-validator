# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, Protocol

import yaml

from manifest_validator.models import Finding, Tree, Verdict

logger = logging.getLogger(__name__)

MANIFEST_SUFFIXES = (".yaml", ".yml")


class ProgressSink(Protocol):
    def __call__(self, phase: str, message: str) -> None: ...


class Checker(Protocol):
    """One check's opinion of one tree.

    A checker owns its own pass/fail rule. The service aggregates verdicts and
    never second-guesses one.
    """

    @property
    def name(self) -> str: ...

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict: ...


def _documents(tree: Tree) -> Iterator[tuple[str, int, Any | None, str | None]]:
    """Yield (path, index, document, parse_error) for every manifest document."""
    for path in sorted(tree.files):
        if not path.endswith(MANIFEST_SUFFIXES):
            continue
        raw = tree.files[path]
        try:
            documents = list(yaml.safe_load_all(raw))
        except yaml.YAMLError as exc:
            yield path, 0, None, str(exc)
            continue
        for index, document in enumerate(documents):
            yield path, index, document, None


def _ruleset_digest(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8"))
        digest.update(b"\x00")
    return f"sha256:{digest.hexdigest()}"


class StructuralChecker:
    """Every document parses and carries apiVersion, kind and metadata.name.

    Cheap, deterministic, and no reason ever to schedule a pod for it.
    """

    version = "1"

    @property
    def name(self) -> str:
        return "structural"

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        progress("running", f"structural: {len(tree)} files")
        findings: list[Finding] = []
        for path, index, document, parse_error in _documents(tree):
            resource = f"{path}#{index}"
            if parse_error is not None:
                findings.append(
                    Finding(
                        rule_id="structural/parse",
                        severity="critical",
                        message=f"document does not parse: {parse_error}",
                        file=path,
                        resource=resource,
                    )
                )
                continue
            if document is None:
                continue
            if not isinstance(document, dict):
                findings.append(
                    Finding(
                        rule_id="structural/not-a-mapping",
                        severity="critical",
                        message=f"document is {type(document).__name__}, not a mapping",
                        file=path,
                        resource=resource,
                    )
                )
                continue
            for key in ("apiVersion", "kind"):
                if not isinstance(document.get(key), str) or not document[key].strip():
                    findings.append(
                        Finding(
                            rule_id=f"structural/missing-{key.lower()}",
                            severity="critical",
                            message=f"document is missing {key}",
                            file=path,
                            resource=resource,
                        )
                    )
            metadata = document.get("metadata")
            name = metadata.get("name") if isinstance(metadata, dict) else None
            if not isinstance(name, str) or not name.strip():
                findings.append(
                    Finding(
                        rule_id="structural/missing-name",
                        severity="critical",
                        message="document is missing metadata.name",
                        file=path,
                        resource=resource,
                    )
                )
        return Verdict(
            passed=not findings,
            tool=self.name,
            tool_version=self.version,
            ruleset_digest=_ruleset_digest(self.name, self.version),
            findings=tuple(findings),
        )


@dataclass(frozen=True)
class ImagePolicyChecker:
    """Image references must be pinned and come from an allowed registry.

    The first rule with teeth: it fails for a real reason before any scanner
    exists, which is what exercises the red path end to end.
    """

    allowed_registries: tuple[str, ...]
    require_pinned: bool = True
    version: str = "1"

    @property
    def name(self) -> str:
        return "image-policy"

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        progress("running", f"image-policy: {len(tree)} files")
        findings: list[Finding] = []
        for path, index, document, parse_error in _documents(tree):
            if parse_error is not None or not isinstance(document, dict):
                continue
            for reference in _image_references(document):
                findings.extend(self._findings_for(reference, path, f"{path}#{index}"))
        return Verdict(
            passed=not findings,
            tool=self.name,
            tool_version=self.version,
            ruleset_digest=_ruleset_digest(
                self.name, self.version, *sorted(self.allowed_registries)
            ),
            findings=tuple(findings),
        )

    def _findings_for(
        self, reference: str, path: str, resource: str
    ) -> Iterator[Finding]:
        if self.allowed_registries and not any(
            reference.startswith(registry) for registry in self.allowed_registries
        ):
            yield Finding(
                rule_id="image-policy/registry-not-allowed",
                severity="high",
                message=f"image {reference!r} is not from an allowed registry",
                file=path,
                resource=resource,
            )
        if self.require_pinned and not _is_pinned(reference):
            yield Finding(
                rule_id="image-policy/unpinned",
                severity="high",
                message=f"image {reference!r} is not pinned to a digest or tag",
                file=path,
                resource=resource,
            )


def _image_references(node: Any) -> Iterator[str]:
    """Every `image:` string anywhere in a document.

    Deliberately structure-agnostic: images appear under containers,
    initContainers, and in CRD spec fields this service does not model.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "image" and isinstance(value, str) and value.strip():
                yield value
            else:
                yield from _image_references(value)
    elif isinstance(node, list):
        for item in node:
            yield from _image_references(item)


def _is_pinned(reference: str) -> bool:
    if "@sha256:" in reference:
        return True
    _, _, last = reference.rpartition("/")
    tag = last.partition(":")[2]
    return bool(tag) and tag != "latest"
