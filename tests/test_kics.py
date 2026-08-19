# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from manifest_validator.commands import CommandOutcome, SubprocessRunner, write_tree
from manifest_validator.errors import CheckTimeout, MalformedTree
from manifest_validator.kics import KicsChecker
from manifest_validator.models import Tree

DIGEST = "sha256:" + "a" * 64
TREE = Tree(files={"a.yaml": b"apiVersion: v1\n", "nested/b.yaml": b"kind: X\n"})


def _noop(phase: str, message: str) -> None:
    return None


def _flag(argv: tuple[str, ...], name: str) -> str | None:
    return argv[argv.index(name) + 1] if name in argv else None


class StubRunner:
    """Writes a report where the checker told KICS to put one, then reports."""

    def __init__(
        self, exit_code: int = 0, report: dict[str, Any] | None = None
    ) -> None:
        self._exit_code = exit_code
        self._report = report
        self.argv: tuple[str, ...] = ()
        self.cwd: Path | None = None

    def run(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
    ) -> CommandOutcome:
        self.argv = argv
        self.cwd = cwd
        if self._report is not None:
            output = _flag(argv, "--output-path")
            assert output is not None
            Path(output, "results.json").write_text(json.dumps(self._report))
        return CommandOutcome(exit_code=self._exit_code, stdout="")


def _checker(runner: object, **kwargs: object) -> KicsChecker:
    return KicsChecker(**({"check_name": "kics", "runner": runner} | kwargs))  # ty: ignore


def _report(
    queries: list[dict[str, Any]] | None = None, **extra: Any
) -> dict[str, Any]:
    return {"kics_version": "v2.1.20", "queries": queries or [], **extra}


HIGH = {
    "query_id": "abc-123",
    "severity": "HIGH",
    "description": "container runs as root",
    "files": [{"file_name": "a.yaml", "resource_name": "x"}],
}


def test_the_tree_is_the_working_directory() -> None:
    """KICS reports locations relative to its cwd, and those reach a PR."""
    runner = StubRunner(report=_report())
    _checker(runner).run(DIGEST, TREE, _noop)
    assert _flag(runner.argv, "--path") == "."
    assert runner.cwd is not None and runner.cwd.name == "tree"


def test_the_tree_is_materialised_for_the_scanner() -> None:
    seen: dict[str, list[str]] = {}

    class Recorder:
        def run(
            self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
        ) -> CommandOutcome:
            seen["files"] = sorted(str(p.relative_to(cwd)) for p in cwd.rglob("*.yaml"))
            return CommandOutcome(exit_code=0, stdout="")

    _checker(Recorder()).run(DIGEST, TREE, _noop)
    assert seen["files"] == ["a.yaml", "nested/b.yaml"]


def test_the_workspace_is_removed_after_the_check() -> None:
    runner = StubRunner(report=_report())
    _checker(runner).run(DIGEST, TREE, _noop)
    assert runner.cwd is not None and not runner.cwd.exists()


def test_config_chooses_types_and_exclusions_and_nothing_else() -> None:
    """The rest of the command line is the image's, or the parser's contract."""
    runner = StubRunner(report=_report())
    _checker(
        runner,
        types=("Kubernetes", "Crossplane"),
        exclude_severities=("medium", "low"),
    ).run(DIGEST, TREE, _noop)
    assert _flag(runner.argv, "--type") == "Kubernetes,Crossplane"
    assert _flag(runner.argv, "--exclude-severities") == "medium,low"
    assert _flag(runner.argv, "--queries-path") == "/opt/kics/assets/queries"
    assert _flag(runner.argv, "--report-formats") == "json"


def test_types_and_exclusions_are_omitted_when_unset() -> None:
    runner = StubRunner(report=_report())
    _checker(runner).run(DIGEST, TREE, _noop)
    assert "--type" not in runner.argv
    assert "--exclude-severities" not in runner.argv


def test_a_clean_scan_passes() -> None:
    verdict = _checker(StubRunner(report=_report())).run(DIGEST, TREE, _noop)
    assert verdict.passed
    assert verdict.findings == ()


def test_findings_are_read_from_the_report() -> None:
    runner = StubRunner(exit_code=50, report=_report([HIGH]))
    verdict = _checker(runner).run(DIGEST, TREE, _noop)
    assert not verdict.passed
    assert [f.rule_id for f in verdict.findings] == ["abc-123"]
    assert verdict.findings[0].severity == "high"
    assert verdict.findings[0].file == "a.yaml"


def test_the_version_is_the_one_that_produced_the_report() -> None:
    """Not one config asserted, which could disagree with the image."""
    runner = StubRunner(report=_report(kics_version="v9.9.9"))
    assert _checker(runner).run(DIGEST, TREE, _noop).tool_version == "v9.9.9"


def test_the_ruleset_digest_follows_version_and_selection() -> None:
    def digest(**kwargs: object) -> str:
        return (
            _checker(StubRunner(report=_report()), **kwargs)
            .run(DIGEST, TREE, _noop)
            .ruleset_digest
        )

    base = digest(types=("Kubernetes",))
    assert digest(types=("Kubernetes",)) == base
    assert digest(types=("Kubernetes", "Crossplane")) != base
    assert digest(types=("Kubernetes",), exclude_severities=("low",)) != base


def test_an_unreadable_report_fails_rather_than_passing_silently() -> None:
    verdict = _checker(StubRunner(exit_code=0)).run(DIGEST, TREE, _noop)
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "kics/unparseable-output"


def test_a_non_zero_exit_with_no_findings_still_explains_itself() -> None:
    """Otherwise this would be a red verdict with nothing in it."""
    verdict = _checker(StubRunner(exit_code=126, report=_report())).run(
        DIGEST, TREE, _noop
    )
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "kics/non-zero-exit"
    assert "126" in verdict.findings[0].message


def test_write_tree_refuses_a_path_that_escapes_the_workspace(tmp_path: Path) -> None:
    with pytest.raises(MalformedTree):
        write_tree(Tree(files={"../escape.yaml": b""}), tmp_path)


def test_a_command_that_overruns_its_timeout_is_a_check_timeout() -> None:
    with pytest.raises(CheckTimeout):
        SubprocessRunner().run(("sleep", "5"), Path.cwd(), timeout_seconds=1)


def test_a_command_that_does_not_exist_is_a_check_timeout() -> None:
    with pytest.raises(CheckTimeout):
        SubprocessRunner().run(("no-such-binary-here",), Path.cwd(), timeout_seconds=5)


def test_the_command_runs_without_a_shell() -> None:
    """No shell means no word splitting, globbing or substitution in a check."""
    outcome = SubprocessRunner().run(("echo", "$HOME; ls"), Path.cwd(), 10)
    assert outcome.stdout.strip() == "$HOME; ls"
