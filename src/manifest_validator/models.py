# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

SEVERITY_ORDER: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")


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
