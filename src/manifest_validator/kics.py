# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import hashlib
import json
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from manifest_validator.checks import ProgressSink
from manifest_validator.commands import CommandRunner, write_tree
from manifest_validator.config import PolicyException
from manifest_validator.models import Finding, Severity, Tree, Verdict

logger = logging.getLogger(__name__)

# manifest-builder writes this as the first line of every file it renders from a
# release. Files it synthesises itself — namespaces — have no header and so can
# never be accepted by provenance.
SOURCE_PREFIX = "# Source:"

# Not configurable: the tree is the working directory, and the config lives in
# the repository that generates the tree, so a movable queries path would let a
# tree supply the queries used to scan it.
BINARY = "kics"
QUERIES_PATH = "/opt/kics/assets/queries"
LIBRARIES_PATH = "/opt/kics/assets/libraries"

REPORT_NAME = "results.json"


@dataclass(frozen=True)
class KicsChecker:
    check_name: str
    runner: CommandRunner
    types: tuple[str, ...] = ()
    exclude_severities: tuple[str, ...] = ()
    exclude_queries: tuple[str, ...] = ()
    timeout_seconds: int = 600
    exceptions: tuple[PolicyException, ...] = ()

    @property
    def name(self) -> str:
        return self.check_name

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        progress("running", f"{self.check_name}: {len(tree)} files")
        with tempfile.TemporaryDirectory(prefix="manifest-validator-") as workspace:
            tree_dir = Path(workspace) / "tree"
            output_dir = Path(workspace) / "out"
            tree_dir.mkdir()
            output_dir.mkdir()
            write_tree(tree, tree_dir)
            outcome = self.runner.run(
                self._argv(output_dir), tree_dir, self.timeout_seconds
            )
            report = _read_report(output_dir / REPORT_NAME)
        findings = _findings(
            report,
            outcome.exit_code,
            self.check_name,
            self.exceptions,
            _provenance(tree),
        )
        accepted = sum(1 for f in findings if f.accepted is not None)
        progress(
            "classified",
            f"{self.check_name}: {len(findings)} findings, {accepted} accepted",
        )
        return Verdict(
            # Not `exit_code == 0`: KICS exits non-zero whenever it reports
            # anything at all, accepted or not. An exit code that no finding
            # explains is itself a finding, below.
            passed=all(f.accepted is not None for f in findings),
            tool=self.check_name,
            tool_version=_version(report),
            ruleset_digest=self._ruleset_digest(report),
            findings=findings,
        )

    def _argv(self, output_dir: Path) -> tuple[str, ...]:
        # `--path .`, not the absolute path: KICS reports locations relative to
        # its working directory, and those reach a pull request.
        argv = [
            BINARY,
            "scan",
            "--path",
            ".",
            "--queries-path",
            QUERIES_PATH,
            "--libraries-path",
            LIBRARIES_PATH,
            "--report-formats",
            "json",
            "--output-path",
            str(output_dir),
            "--ci",
        ]
        if self.types:
            argv += ["--type", ",".join(self.types)]
        if self.exclude_severities:
            argv += ["--exclude-severities", ",".join(self.exclude_severities)]
        if self.exclude_queries:
            argv += ["--exclude-queries", ",".join(self.exclude_queries)]
        return tuple(argv)

    def _ruleset_digest(self, report: dict[str, Any] | None) -> str:
        digest = hashlib.sha256()
        for part in (
            _version(report),
            *sorted(self.types),
            *sorted(self.exclude_severities),
            *sorted(self.exclude_queries),
            *sorted(
                f"{e.source}|{e.query}|{e.similarity_id}|{e.reason}"
                for e in self.exceptions
            ),
        ):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x00")
        return f"sha256:{digest.hexdigest()}"


def _version(report: dict[str, Any] | None) -> str:
    if report is None:
        return "unknown"
    version = report.get("kics_version")
    return version if isinstance(version, str) and version.strip() else "unknown"


def _provenance(tree: Tree) -> dict[str, str]:
    sources: dict[str, str] = {}
    for path, content in tree.files.items():
        first_line = content.split(b"\n", 1)[0].decode("utf-8", "replace").strip()
        if first_line.startswith(SOURCE_PREFIX):
            sources[path] = first_line[len(SOURCE_PREFIX) :].strip()
    return sources


def _source_of(file_name: str | None, provenance: dict[str, str]) -> str | None:
    """Map a reported path back onto a tree path.

    KICS reports relative to its working directory, but has been seen to prefix
    the result with `./` or to climb out of the tree and back in, so an exact
    match is not enough.
    """
    if not file_name:
        return None
    parts = [p for p in PurePosixPath(file_name).parts if p not in (".", "..")]
    if not parts:
        return None
    candidate = "/".join(parts)
    if candidate in provenance:
        return provenance[candidate]
    matches = [path for path in provenance if candidate.endswith(path)]
    if len(matches) != 1:
        return None
    return provenance[matches[0]]


def _accept(
    exceptions: tuple[PolicyException, ...],
    matched: set[int],
    *,
    query_id: str,
    query_name: str,
    similarity_id: str | None,
    source: str | None,
) -> str | None:
    for index, exception in enumerate(exceptions):
        if exception.similarity_id:
            hit = similarity_id is not None and exception.similarity_id == similarity_id
        else:
            hit = (
                source is not None
                and exception.source == source
                and exception.query in (query_id, query_name)
            )
        if hit:
            matched.add(index)
            return exception.reason
    return None


def _findings(
    report: dict[str, Any] | None,
    exit_code: int,
    check_name: str,
    exceptions: tuple[PolicyException, ...] = (),
    provenance: dict[str, str] | None = None,
) -> tuple[Finding, ...]:
    if report is None:
        return (
            Finding(
                rule_id=f"{check_name}/unparseable-output",
                severity="critical",
                message=f"no readable JSON report at {REPORT_NAME} (exit {exit_code})",
            ),
        )
    sources = provenance or {}
    matched: set[int] = set()
    findings: list[Finding] = []
    for query in report.get("queries", []):
        severity = str(query.get("severity", "info")).lower()
        query_id = str(query.get("query_id", f"{check_name}/unknown"))
        query_name = str(query.get("query_name", ""))
        for location in query.get("files", []):
            file_name = location.get("file_name")
            similarity_id = location.get("similarity_id")
            findings.append(
                Finding(
                    rule_id=query_id,
                    severity=_severity(severity),
                    message=str(query.get("description", query_name)),
                    file=file_name,
                    resource=location.get("resource_name"),
                    similarity_id=similarity_id,
                    accepted=_accept(
                        exceptions,
                        matched,
                        query_id=query_id,
                        query_name=query_name,
                        similarity_id=similarity_id,
                        source=_source_of(file_name, sources),
                    ),
                )
            )
    # Before the exception notices below, which must not stand in for a finding
    # and let a crashed scan look like a reported one.
    if not findings and exit_code != 0:
        findings.append(
            Finding(
                rule_id=f"{check_name}/non-zero-exit",
                severity="critical",
                message=f"reported no findings but exited {exit_code}",
            )
        )
    findings.extend(
        # An exception that matches nothing is the signal that expiry dates were
        # meant to produce, and it fires only when the exception actually dies.
        # It is reported as accepted: a fix upstream must not fail a build.
        Finding(
            rule_id=f"{check_name}/unused-exception",
            severity="info",
            message=f"exception no longer matches anything: {e.describe()}",
            accepted="reported for review; remove the exception",
        )
        for index, e in enumerate(exceptions)
        if index not in matched
    )
    return tuple(findings)


def _read_report(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text())
    except OSError, json.JSONDecodeError:
        logger.exception("could not read %s", path)
        return None
    return payload if isinstance(payload, dict) else None


def _severity(value: str) -> Severity:
    if value in ("critical", "high", "medium", "low", "info"):
        return value
    return "info"
