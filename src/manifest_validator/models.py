# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Literal

import yaml

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")

MANIFEST_SUFFIXES = (".yaml", ".yml")

type Document = tuple[str, int, Any | None, str | None]
"""(path, index, document, parse_error) for one document in a manifest file."""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file: str | None = None
    resource: str | None = None
    similarity_id: str | None = None
    """The scanner's stable identity for this finding, when it has one.

    Reported so that a one-off suppression can be written from the verdict
    itself, rather than by re-running the scanner by hand to recover the id.
    """

    accepted: str | None = None
    """Why this finding does not fail the verdict, or None if it does.

    Accepted findings stay in the report. A verdict that hid what it tolerated
    could not be reviewed, which is the whole objection to a count.
    """

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "resource": self.resource,
            "message": self.message,
            "similarity_id": self.similarity_id,
            "accepted": self.accepted,
        }


@dataclass(frozen=True)
class Verdict:
    """One check's opinion of one tree.

    `passed` is decided here, by the check that produced the findings, and is
    never recomputed from `findings` by a caller.
    """

    passed: bool
    tool: str
    tool_version: str
    ruleset_digest: str
    findings: tuple[Finding, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "ruleset_digest": self.ruleset_digest,
            "findings": [f.as_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class ValidationResult:
    digest: str
    verdicts: tuple[Verdict, ...]
    cached: bool = False

    @property
    def passed(self) -> bool:
        return all(v.passed for v in self.verdicts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "digest": self.digest,
            "cached": self.cached,
            "verdicts": [v.as_dict() for v in self.verdicts],
        }


@dataclass(frozen=True)
class Tree:
    """A generated manifest tree: relative path to file content."""

    files: Mapping[str, bytes] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.files)

    @cached_property
    def documents(self) -> tuple[Document, ...]:
        """Every manifest document, parsed once however many checks read it."""
        parsed: list[Document] = []
        for path in sorted(self.files):
            if not path.endswith(MANIFEST_SUFFIXES):
                continue
            try:
                # libyaml: the pure-Python loader was most of a validation's time.
                documents = list(
                    yaml.load_all(self.files[path], Loader=yaml.CSafeLoader)
                )
            except yaml.YAMLError as exc:
                parsed.append((path, 0, None, str(exc)))
                continue
            parsed.extend(
                (path, index, doc, None) for index, doc in enumerate(documents)
            )
        return tuple(parsed)
