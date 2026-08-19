# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import hashlib
import json
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from manifest_validator.checks import ProgressSink
from manifest_validator.commands import CommandRunner, write_tree
from manifest_validator.models import Finding, Severity, Tree, Verdict

logger = logging.getLogger(__name__)

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
    timeout_seconds: int = 600

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
        findings = _findings(report, outcome.exit_code, self.check_name)
        return Verdict(
            passed=outcome.exit_code == 0 and not findings,
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
        return tuple(argv)

    def _ruleset_digest(self, report: dict[str, Any] | None) -> str:
        digest = hashlib.sha256()
        for part in (
            _version(report),
            *sorted(self.types),
            *sorted(self.exclude_severities),
        ):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x00")
        return f"sha256:{digest.hexdigest()}"


def _version(report: dict[str, Any] | None) -> str:
    if report is None:
        return "unknown"
    version = report.get("kics_version")
    return version if isinstance(version, str) and version.strip() else "unknown"


def _findings(
    report: dict[str, Any] | None, exit_code: int, check_name: str
) -> tuple[Finding, ...]:
    if report is None:
        return (
            Finding(
                rule_id=f"{check_name}/unparseable-output",
                severity="critical",
                message=f"no readable JSON report at {REPORT_NAME} (exit {exit_code})",
            ),
        )
    findings: list[Finding] = []
    for query in report.get("queries", []):
        severity = str(query.get("severity", "info")).lower()
        for location in query.get("files", []):
            findings.append(
                Finding(
                    rule_id=str(query.get("query_id", f"{check_name}/unknown")),
                    severity=_severity(severity),
                    message=str(query.get("description", query.get("query_name", ""))),
                    file=location.get("file_name"),
                    resource=location.get("resource_name"),
                )
            )
    if not findings and exit_code != 0:
        findings.append(
            Finding(
                rule_id=f"{check_name}/non-zero-exit",
                severity="critical",
                message=f"reported no findings but exited {exit_code}",
            )
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
