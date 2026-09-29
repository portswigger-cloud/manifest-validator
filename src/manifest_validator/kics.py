# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import hashlib
import json
import logging
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from manifest_validator.checks import ProgressSink
from manifest_validator.commands import CommandRunner, write_tree
from manifest_validator.config import PolicyException
from manifest_validator.models import Finding, Severity, Tree, Verdict
from manifest_validator.scan_cache import FileScanCache, Scan, resolve_path

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

# Part of every remembered result's key: change it whenever KicsScanner.encode
# does, so results written in the old shape are never read in the new one.
RESULT_ENCODING = "kics-result-v1"


@dataclass(frozen=True)
class KicsResult:
    """A finding as KICS reported it, with the query name exceptions match on."""

    finding: Finding
    query_name: str = ""

    @property
    def file(self) -> str | None:
        return self.finding.file


@dataclass(frozen=True)
class KicsScanner:
    """Runs KICS and reports what it found, before any exception is applied."""

    check_name: str
    runner: CommandRunner
    types: tuple[str, ...] = ()
    exclude_severities: tuple[str, ...] = ()
    exclude_queries: tuple[str, ...] = ()
    timeout_seconds: int = 600
    version: str | None = None
    """The KICS this image was built with, known before any scan runs."""

    @property
    def cache_identity(self) -> str | None:
        if self.version is None:
            return None
        return "\x00".join(
            (
                RESULT_ENCODING,
                self.version,
                *sorted(self.types),
                "",
                *sorted(self.exclude_severities),
                "",
                *sorted(self.exclude_queries),
            )
        )

    def encode(self, result: KicsResult) -> dict[str, Any]:
        finding = result.finding
        return {
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "message": finding.message,
            "file": finding.file,
            "resource": finding.resource,
            "similarity_id": finding.similarity_id,
            "query_name": result.query_name,
        }

    def decode(self, data: dict[str, Any]) -> KicsResult:
        return KicsResult(
            Finding(
                rule_id=str(data["rule_id"]),
                severity=_severity(str(data["severity"])),
                message=str(data["message"]),
                file=data["file"],
                resource=data["resource"],
                similarity_id=data["similarity_id"],
            ),
            query_name=str(data["query_name"]),
        )

    def scan(self, tree: Tree, progress: ProgressSink) -> Scan[KicsResult]:
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
        version = _version(report)
        mismatched = self.version not in (None, version)
        if mismatched:
            logger.error(
                "%s: image was built with KICS %s but %s ran; not remembering",
                self.check_name,
                self.version,
                version,
            )
        return Scan(
            tool_version=version,
            findings=_findings(report, outcome.exit_code, self.check_name),
            rememberable=not mismatched,
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


@dataclass(frozen=True)
class KicsChecker:
    scanner: KicsScanner
    exceptions: tuple[PolicyException, ...] = ()
    cache: FileScanCache[KicsResult] = field(
        default_factory=FileScanCache, compare=False
    )

    @property
    def name(self) -> str:
        return self.scanner.check_name

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        scan = self.cache.scan(self.scanner, tree, progress)
        findings = _classify(
            scan.findings, self.name, self.exceptions, _provenance(tree)
        )
        accepted = sum(1 for f in findings if f.accepted is not None)
        unchanged = (
            f", {scan.reused_files} of {len(tree)} files unchanged since scanned"
            if scan.reused_files
            else ""
        )
        progress(
            "classified",
            f"{self.name}: {len(findings)} findings, {accepted} accepted{unchanged}",
        )
        return Verdict(
            # Not the exit code: KICS exits non-zero whenever it reports
            # anything at all, accepted or not. An exit code that no finding
            # explains is itself a finding, from the scanner.
            passed=all(f.accepted is not None for f in findings),
            tool=self.name,
            tool_version=scan.tool_version,
            ruleset_digest=self._ruleset_digest(scan.tool_version),
            findings=findings,
        )

    def _ruleset_digest(self, tool_version: str) -> str:
        digest = hashlib.sha256()
        for part in (
            tool_version,
            *sorted(self.scanner.types),
            *sorted(self.scanner.exclude_severities),
            *sorted(self.scanner.exclude_queries),
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
    path = resolve_path(file_name, provenance)
    return provenance[path] if path is not None else None


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
    report: dict[str, Any] | None, exit_code: int, check_name: str
) -> tuple[KicsResult, ...]:
    if report is None:
        return (
            KicsResult(
                Finding(
                    rule_id=f"{check_name}/unparseable-output",
                    severity="critical",
                    message=f"no readable JSON report at {REPORT_NAME} "
                    f"(exit {exit_code})",
                )
            ),
        )
    # KICS reports in a different order from run to run.
    results = sorted(
        (
            KicsResult(
                Finding(
                    rule_id=str(query.get("query_id", f"{check_name}/unknown")),
                    severity=_severity(str(query.get("severity", "info")).lower()),
                    message=str(query.get("description", query.get("query_name", ""))),
                    file=location.get("file_name"),
                    resource=location.get("resource_name"),
                    similarity_id=location.get("similarity_id"),
                ),
                query_name=str(query.get("query_name", "")),
            )
            for query in report.get("queries", [])
            for location in query.get("files", [])
        ),
        key=_report_order,
    )
    if not results and exit_code != 0:
        results.append(
            KicsResult(
                Finding(
                    rule_id=f"{check_name}/non-zero-exit",
                    severity="critical",
                    message=f"reported no findings but exited {exit_code}",
                )
            )
        )
    return tuple(results)


def _classify(
    results: tuple[KicsResult, ...],
    check_name: str,
    exceptions: tuple[PolicyException, ...],
    provenance: dict[str, str],
) -> tuple[Finding, ...]:
    matched: set[int] = set()
    classified = [
        replace(
            result.finding,
            accepted=_accept(
                exceptions,
                matched,
                query_id=result.finding.rule_id,
                query_name=result.query_name,
                similarity_id=result.finding.similarity_id,
                source=_source_of(result.file, provenance),
            ),
        )
        for result in results
    ]
    classified.extend(
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
    return tuple(classified)


def _report_order(result: KicsResult) -> tuple[str, ...]:
    f = result.finding
    return (
        f.file or "",
        f.rule_id,
        f.resource or "",
        f.similarity_id or "",
        f.message,
    )


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
