# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from manifest_validator.checks import ProgressSink
from manifest_validator.errors import CheckTimeout, MalformedTree
from manifest_validator.models import Finding, Severity, Tree, Verdict

logger = logging.getLogger(__name__)

TREE_PLACEHOLDER = "{tree}"
OUTPUT_PLACEHOLDER = "{output}"


@dataclass(frozen=True)
class CommandOutcome:
    exit_code: int
    stdout: str


class CommandRunner(Protocol):
    def run(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
    ) -> CommandOutcome: ...


class SubprocessRunner:
    """Runs a tool as a child process of this service.

    The tool gets the process's own privileges, which is the trade this service
    makes: no scanner here needs egress or a credential, so isolating one in its
    own pod bought nothing but a Job to schedule and an image to pull.
    """

    def run(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
    ) -> CommandOutcome:
        try:
            completed = subprocess.run(  # noqa: S603
                argv,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CheckTimeout(
                f"{argv[0]} did not finish in {timeout_seconds}s"
            ) from exc
        except OSError as exc:
            raise CheckTimeout(f"could not run {argv[0]}: {exc}") from exc
        return CommandOutcome(
            exit_code=completed.returncode,
            stdout=completed.stdout + completed.stderr,
        )


def write_tree(tree: Tree, destination: Path) -> None:
    """Materialise a tree on disk for a tool that reads files.

    `from_tar_gz` already rejects absolute and traversing paths, but this is
    where a bad path would become a write outside the workspace, so it is
    checked again here rather than trusted from a caller.
    """
    root = destination.resolve()
    for path, content in tree.files.items():
        target = (root / path).resolve()
        if not target.is_relative_to(root):
            raise MalformedTree(f"{path!r} escapes the workspace")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


@dataclass(frozen=True)
class CommandChecker:
    """A check that runs a tool in this container, over a materialised tree."""

    check_name: str
    command: tuple[str, ...]
    runner: CommandRunner
    ruleset_digest: str
    tool_version: str
    timeout_seconds: int = 600
    findings_format: str = "exit-code"

    @property
    def name(self) -> str:
        return self.check_name

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        """The tool runs with the tree as its working directory.

        That is what makes a tool report `a/b.yaml` rather than a path through
        the temporary workspace, which would otherwise reach a pull request.
        """
        progress("running", f"{self.check_name}: {len(tree)} files")
        with tempfile.TemporaryDirectory(prefix="manifest-validator-") as workspace:
            tree_dir = Path(workspace) / "tree"
            output_dir = Path(workspace) / "out"
            tree_dir.mkdir()
            output_dir.mkdir()
            write_tree(tree, tree_dir)
            outcome = self.runner.run(
                _substitute(self.command, tree_dir, output_dir),
                tree_dir,
                self.timeout_seconds,
            )
            findings = _parse_findings(
                self.findings_format, outcome, output_dir, self.check_name
            )
        return Verdict(
            passed=outcome.exit_code == 0 and not findings,
            tool=self.check_name,
            tool_version=self.tool_version,
            ruleset_digest=self.ruleset_digest,
            findings=findings,
        )


def _substitute(
    command: tuple[str, ...], tree_dir: Path, output_dir: Path
) -> tuple[str, ...]:
    return tuple(
        part.replace(TREE_PLACEHOLDER, str(tree_dir)).replace(
            OUTPUT_PLACEHOLDER, str(output_dir)
        )
        for part in command
    )


def _parse_findings(
    findings_format: str, outcome: CommandOutcome, output_dir: Path, check_name: str
) -> tuple[Finding, ...]:
    if findings_format == "kics":
        return _parse_kics(output_dir)
    if outcome.exit_code == 0:
        return ()
    return (
        Finding(
            rule_id=f"{check_name}/non-zero-exit",
            severity="critical",
            message=f"exited {outcome.exit_code}: {outcome.stdout.strip()[-2000:]}",
        ),
    )


def _parse_kics(output_dir: Path) -> tuple[Finding, ...]:
    payload = _read_report(output_dir / "results.json")
    if payload is None:
        return (
            Finding(
                rule_id="kics/unparseable-output",
                severity="critical",
                message="no readable JSON report at results.json",
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


def _read_report(path: Path) -> dict[str, Any] | None:
    """Read the tool's own report file rather than scraping its output.

    A report is pretty-printed over many lines, so nothing useful can be
    recovered from stdout line by line.
    """
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
