# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import itertools
from collections.abc import Callable

import pytest

from manifest_validator.checks import ProgressSink
from manifest_validator.errors import DigestMismatch, UnknownCheck
from manifest_validator.models import Finding, Tree, Verdict
from manifest_validator.service import ValidationService
from manifest_validator.trees import compute_digest

FILES = {"a.yaml": b"apiVersion: v1\nkind: Namespace\nmetadata:\n  name: a\n"}


class StubChecker:
    def __init__(self, name: str, passed: bool = True) -> None:
        self._name = name
        self._passed = passed
        self.calls = 0
        self.seen_digests: list[str] = []

    @property
    def name(self) -> str:
        return self._name

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        self.calls += 1
        self.seen_digests.append(digest)
        progress("running", self._name)
        findings = (
            ()
            if self._passed
            else (Finding(rule_id="stub/fail", severity="high", message="no"),)
        )
        return Verdict(
            passed=self._passed,
            tool=self._name,
            tool_version="1",
            ruleset_digest="sha256:stub",
            findings=findings,
        )


class ExplodingChecker:
    @property
    def name(self) -> str:
        return "boom"

    def run(self, digest: str, tree: Tree, progress: ProgressSink) -> Verdict:
        raise RuntimeError("kaboom")


def _service(*checkers: object) -> ValidationService:
    mapping = {c.name: c for c in checkers}  # ty: ignore
    return ValidationService(mapping)  # ty: ignore


def _ticking_clock(step: float) -> Callable[[], float]:
    """A clock that advances by `step` every time it is read."""
    readings = itertools.count(step=step)
    return lambda: next(readings)


def _events() -> tuple[list[tuple[str, str]], ProgressSink]:
    seen: list[tuple[str, str]] = []

    def sink(phase: str, message: str) -> None:
        seen.append((phase, message))

    return seen, sink


def test_passes_when_every_check_passes() -> None:
    service = _service(StubChecker("one"), StubChecker("two"))
    _, sink = _events()
    result = service.validate(compute_digest(FILES), FILES, sink)
    assert result.passed
    assert len(result.verdicts) == 2


def test_fails_when_any_check_fails() -> None:
    service = _service(StubChecker("one"), StubChecker("two", passed=False))
    _, sink = _events()
    assert not service.validate(compute_digest(FILES), FILES, sink).passed


def test_rejects_a_claimed_digest_that_does_not_match_the_bytes() -> None:
    service = _service(StubChecker("one"))
    _, sink = _events()
    with pytest.raises(DigestMismatch):
        service.validate("sha256:" + "0" * 64, FILES, sink)


def test_rejects_an_unknown_check_name() -> None:
    service = _service(StubChecker("one"))
    _, sink = _events()
    with pytest.raises(UnknownCheck):
        service.validate(compute_digest(FILES), FILES, sink, ["nope"])


def test_identical_content_is_not_rescanned() -> None:
    checker = StubChecker("one")
    service = _service(checker)
    _, sink = _events()
    digest = compute_digest(FILES)
    service.validate(digest, FILES, sink)
    second = service.validate(digest, FILES, sink)
    assert checker.calls == 1
    assert second.cached


def test_a_different_check_set_is_a_different_cache_key() -> None:
    one, two = StubChecker("one"), StubChecker("two")
    service = _service(one, two)
    _, sink = _events()
    digest = compute_digest(FILES)
    service.validate(digest, FILES, sink, ["one"])
    service.validate(digest, FILES, sink, ["one", "two"])
    assert two.calls == 1


def test_a_check_that_raises_fails_closed() -> None:
    service = _service(ExplodingChecker())
    _, sink = _events()
    result = service.validate(compute_digest(FILES), FILES, sink)
    assert not result.passed
    assert result.verdicts[0].findings[0].rule_id == "boom/check-error"


def test_progress_ends_on_a_terminal_phase() -> None:
    service = _service(StubChecker("one", passed=False))
    seen, sink = _events()
    service.validate(compute_digest(FILES), FILES, sink)
    assert seen[-1][0] == "validation-failed"


def test_each_check_reports_how_long_it_took() -> None:
    service = ValidationService(
        {"one": StubChecker("one"), "two": StubChecker("two", passed=False)},
        clock=_ticking_clock(1.5),
    )
    seen, sink = _events()
    result = service.validate(compute_digest(FILES), FILES, sink)
    assert [v.duration_seconds for v in result.verdicts] == [1.5, 1.5]
    assert ("checked", "one: passed in 1.5s") in seen
    assert ("checked", "two: failed in 1.5s") in seen
    assert seen[-1] == ("validation-failed", "1 findings in 7.5s")


def test_a_check_that_raises_still_reports_its_duration() -> None:
    service = ValidationService({"boom": ExplodingChecker()}, clock=_ticking_clock(2))
    seen, sink = _events()
    result = service.validate(compute_digest(FILES), FILES, sink)
    assert result.verdicts[0].duration_seconds == 2
    assert ("checked", "boom: failed in 2.0s") in seen


def test_a_cached_verdict_carries_the_duration_of_the_run_that_made_it() -> None:
    service = ValidationService({"one": StubChecker("one")}, clock=_ticking_clock(1))
    _, sink = _events()
    digest = compute_digest(FILES)
    service.validate(digest, FILES, sink)
    cached = service.validate(digest, FILES, sink)
    assert cached.cached
    assert cached.as_dict()["verdicts"][0]["duration_seconds"] == 1


def _discard(phase: str, message: str) -> None:
    """Ignore progress, for a test that is only about the verdict."""
