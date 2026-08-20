# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from manifest_validator.commands import CommandOutcome, SubprocessRunner, write_tree
from manifest_validator.config import PolicyException
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
    verdict = _checker(StubRunner(exit_code=126, report=_report())).run(
        DIGEST, TREE, _noop
    )
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "kics/non-zero-exit"
    assert "126" in verdict.findings[0].message


SOURCED_TREE = Tree(
    files={
        "cluster/clusterrole-crossplane-admin.yaml": b"# Source: crossplane\nkind: ClusterRole\n",
        "relcoord/deployment-relcoord.yaml": b"# Source: relcoord\nkind: Deployment\n",
        "argo/namespace-argo.yaml": b"apiVersion: v1\nkind: Namespace\n",
    }
)


def _finding(
    file_name: str,
    *,
    query_id: str = "abc-123",
    query_name: str = "RBAC Wildcard In Rule",
    severity: str = "HIGH",
    similarity_id: str = "sim-1",
) -> dict[str, Any]:
    return {
        "query_id": query_id,
        "query_name": query_name,
        "severity": severity,
        "description": query_name,
        "files": [
            {
                "file_name": file_name,
                "resource_name": "x",
                "similarity_id": similarity_id,
            }
        ],
    }


CROSSPLANE_WILDCARD = _finding("cluster/clusterrole-crossplane-admin.yaml")
OUR_ESCALATION = _finding(
    "relcoord/deployment-relcoord.yaml",
    query_id="def-456",
    query_name="Privilege Escalation Allowed",
    similarity_id="sim-2",
)


def _run(report: dict[str, Any], *exceptions: PolicyException, exit_code: int = 50):
    runner = StubRunner(exit_code=exit_code, report=report)
    return _checker(runner, exceptions=exceptions).run(DIGEST, SOURCED_TREE, _noop)


def test_provenance_comes_from_the_source_header() -> None:
    """The tree names its own producer, so no exception has to name a path."""
    verdict = _run(
        _report([CROSSPLANE_WILDCARD]),
        PolicyException(
            source="crossplane", query="RBAC Wildcard In Rule", reason="aggregation"
        ),
    )
    assert verdict.passed
    assert verdict.findings[0].accepted == "aggregation"


def test_an_accepted_finding_is_still_reported() -> None:
    verdict = _run(
        _report([CROSSPLANE_WILDCARD, OUR_ESCALATION]),
        PolicyException(
            source="crossplane", query="RBAC Wildcard In Rule", reason="aggregation"
        ),
    )
    assert len(verdict.findings) == 2
    assert not verdict.passed, "one unaccepted finding still fails the verdict"
    assert [f.accepted for f in verdict.findings] == ["aggregation", None]


def test_an_exception_does_not_leak_across_releases() -> None:
    """Accepting crossplane's wildcards must not accept ours."""
    verdict = _run(
        _report([_finding("relcoord/deployment-relcoord.yaml")]),
        PolicyException(
            source="crossplane", query="RBAC Wildcard In Rule", reason="aggregation"
        ),
    )
    assert not verdict.passed
    assert verdict.findings[0].accepted is None


def test_an_exception_does_not_leak_across_queries() -> None:
    verdict = _run(
        _report([OUR_ESCALATION]),
        PolicyException(
            source="relcoord", query="RBAC Wildcard In Rule", reason="aggregation"
        ),
    )
    assert not verdict.passed


def test_a_query_may_be_named_by_id() -> None:
    verdict = _run(
        _report([CROSSPLANE_WILDCARD]),
        PolicyException(source="crossplane", query="abc-123", reason="by id"),
    )
    assert verdict.passed


def test_a_similarity_id_accepts_one_finding_and_no_other() -> None:
    verdict = _run(
        _report([CROSSPLANE_WILDCARD, OUR_ESCALATION]),
        PolicyException(similarity_id="sim-2", reason="teleport join token name"),
    )
    assert [f.accepted for f in verdict.findings] == [
        None,
        "teleport join token name",
    ]


def test_a_fully_accepted_scan_passes_despite_the_scanner_exit_code() -> None:
    """KICS exits non-zero whenever it reports anything, accepted or not."""
    verdict = _run(
        _report([CROSSPLANE_WILDCARD]),
        PolicyException(source="crossplane", query="abc-123", reason="aggregation"),
        exit_code=50,
    )
    assert verdict.passed


def test_a_file_without_a_source_header_can_never_be_accepted_by_provenance() -> None:
    verdict = _run(
        _report([_finding("argo/namespace-argo.yaml")]),
        PolicyException(source="argo", query="abc-123", reason="tempting"),
    )
    assert not verdict.passed


def test_an_exception_that_matches_nothing_is_reported_but_does_not_fail() -> None:
    """The replacement for expiry dates: a dead exception announces itself."""
    verdict = _run(
        _report([CROSSPLANE_WILDCARD]),
        PolicyException(source="crossplane", query="abc-123", reason="aggregation"),
        PolicyException(source="cilium", query="xyz-789", reason="CNI needs SYS_ADMIN"),
    )
    assert verdict.passed
    unused = [f for f in verdict.findings if f.rule_id == "kics/unused-exception"]
    assert len(unused) == 1
    assert "cilium" in unused[0].message
    assert unused[0].accepted is not None


def test_the_ruleset_digest_follows_the_exceptions() -> None:
    """A verdict must not look identical after the policy has changed."""

    def digest(*exceptions: PolicyException) -> str:
        return _run(_report(), *exceptions, exit_code=0).ruleset_digest

    assert digest() != digest(PolicyException(similarity_id="sim-2", reason="r"))
    assert digest(PolicyException(similarity_id="sim-2", reason="r")) != digest(
        PolicyException(similarity_id="sim-2", reason="different reason")
    )


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


def test_the_similarity_id_is_reported_so_a_suppression_can_be_written() -> None:
    verdict = _run(_report([OUR_ESCALATION]))
    assert verdict.findings[0].similarity_id == "sim-2"
