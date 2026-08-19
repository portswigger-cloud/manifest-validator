# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import json
from pathlib import Path

import pytest

from manifest_validator.commands import (
    CommandChecker,
    CommandOutcome,
    SubprocessRunner,
    write_tree,
)
from manifest_validator.errors import CheckTimeout, MalformedTree
from manifest_validator.models import Tree

DIGEST = "sha256:" + "a" * 64
TREE = Tree(files={"a.yaml": b"apiVersion: v1\n", "nested/b.yaml": b"kind: X\n"})


def _noop(phase: str, message: str) -> None:
    return None


class StubRunner:
    """Records the argv it was given, and optionally writes a report first."""

    def __init__(self, outcome: CommandOutcome, report: dict | None = None) -> None:
        self._outcome = outcome
        self._report = report
        self.argv: tuple[str, ...] = ()

    def run(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
    ) -> CommandOutcome:
        self.argv = argv
        if self._report is not None:
            Path(argv[-1], "results.json").write_text(json.dumps(self._report))
        return self._outcome


def _checker(runner: object, **kwargs: object) -> CommandChecker:
    defaults: dict[str, object] = {
        "check_name": "kics",
        "command": ("kics", "scan", "--path", "{tree}", "--output-path", "{output}"),
        "runner": runner,
        "ruleset_digest": "sha256:rules",
        "tool_version": "v2.1.16",
    }
    return CommandChecker(**(defaults | kwargs))  # ty: ignore


def test_the_tree_is_materialised_where_the_command_is_told_to_look() -> None:
    seen: dict[str, list[str]] = {}

    class Recorder:
        def run(
            self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
        ) -> CommandOutcome:
            root = Path(argv[3])
            seen["files"] = sorted(
                str(p.relative_to(root)) for p in root.rglob("*.yaml")
            )
            return CommandOutcome(exit_code=0, stdout="")

    _checker(Recorder()).run(DIGEST, TREE, _noop)
    assert seen["files"] == ["a.yaml", "nested/b.yaml"]


def test_the_workspace_is_removed_after_the_check() -> None:
    runner = StubRunner(CommandOutcome(exit_code=0, stdout=""))
    _checker(runner).run(DIGEST, TREE, _noop)
    assert not Path(runner.argv[3]).exists()


def test_a_clean_exit_passes() -> None:
    verdict = _checker(StubRunner(CommandOutcome(0, ""))).run(DIGEST, TREE, _noop)
    assert verdict.passed
    assert verdict.tool_version == "v2.1.16"


def test_a_non_zero_exit_fails_with_the_tail_of_the_output() -> None:
    runner = StubRunner(CommandOutcome(exit_code=3, stdout="it went wrong"))
    verdict = _checker(runner).run(DIGEST, TREE, _noop)
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "kics/non-zero-exit"
    assert "it went wrong" in verdict.findings[0].message


def test_kics_findings_are_read_from_the_report_file() -> None:
    """The report is pretty-printed, so it cannot be recovered from stdout."""
    report = {
        "queries": [
            {
                "query_id": "abc-123",
                "severity": "HIGH",
                "description": "container runs as root",
                "files": [{"file_name": "a.yaml", "resource_name": "x"}],
            }
        ]
    }
    runner = StubRunner(CommandOutcome(exit_code=50, stdout=""), report=report)
    verdict = _checker(runner, findings_format="kics").run(DIGEST, TREE, _noop)
    assert not verdict.passed
    assert [f.rule_id for f in verdict.findings] == ["abc-123"]
    assert verdict.findings[0].severity == "high"
    assert verdict.findings[0].file == "a.yaml"


def test_kics_with_no_findings_passes() -> None:
    runner = StubRunner(CommandOutcome(exit_code=0, stdout=""), report={"queries": []})
    verdict = _checker(runner, findings_format="kics").run(DIGEST, TREE, _noop)
    assert verdict.passed
    assert verdict.findings == ()


def test_a_missing_report_fails_rather_than_passing_silently() -> None:
    runner = StubRunner(CommandOutcome(exit_code=0, stdout="no report written"))
    verdict = _checker(runner, findings_format="kics").run(DIGEST, TREE, _noop)
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "kics/unparseable-output"


def test_write_tree_refuses_a_path_that_escapes_the_workspace(tmp_path: Path) -> None:
    with pytest.raises(MalformedTree):
        write_tree(Tree(files={"../escape.yaml": b""}), tmp_path)


def test_a_command_that_overruns_its_timeout_is_a_check_timeout() -> None:
    with pytest.raises(CheckTimeout):
        SubprocessRunner().run(("sleep", "5"), Path.cwd(), timeout_seconds=1)


def test_a_command_that_does_not_exist_is_a_check_timeout() -> None:
    with pytest.raises(CheckTimeout):
        SubprocessRunner().run(("no-such-binary-here",), Path.cwd(), timeout_seconds=5)


def test_the_command_runs_in_the_tree_directory() -> None:
    """A tool reports paths relative to its cwd, and those reach a PR comment."""
    runner = StubRunner(CommandOutcome(exit_code=0, stdout=""))

    class Recorder:
        seen: Path | None = None

        def run(
            self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
        ) -> CommandOutcome:
            Recorder.seen = cwd
            return CommandOutcome(exit_code=0, stdout="")

    _checker(Recorder()).run(DIGEST, TREE, _noop)
    assert Recorder.seen is not None
    assert Recorder.seen.name == "tree"
    assert runner.argv == ()


def test_the_command_runs_without_a_shell() -> None:
    """No shell means no word splitting, globbing or substitution in a check."""
    outcome = SubprocessRunner().run(
        ("echo", "$HOME; ls"), Path.cwd(), timeout_seconds=10
    )
    assert outcome.stdout.strip() == "$HOME; ls"
