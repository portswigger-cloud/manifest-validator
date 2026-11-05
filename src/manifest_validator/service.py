# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import logging
import threading
from collections.abc import Mapping, Sequence

from manifest_validator.checks import Checker, ProgressSink
from manifest_validator.errors import UnknownCheck
from manifest_validator.models import Finding, Tree, ValidationResult, Verdict
from manifest_validator.trees import verify_digest

logger = logging.getLogger(__name__)


class VerdictCache:
    """Dedupes repeat validations of byte-identical trees.

    Keyed on content digest plus the check, so a verdict is valid exactly as
    long as both are unchanged. Machine-driven image bumps regenerate identical
    trees often enough that this is load-bearing, not an optimisation.

    Per check rather than per set of checks, so that a check whose answer is not
    a function of the tree alone can be left out without costing the others
    theirs.
    """

    def __init__(self, max_entries: int = 1024) -> None:
        self._entries: dict[tuple[str, str], Verdict] = {}
        self._order: list[tuple[str, str]] = []
        self._max_entries = max_entries
        self._lock = threading.Lock()

    def get(self, digest: str, check: str) -> Verdict | None:
        with self._lock:
            return self._entries.get((digest, check))

    def put(self, digest: str, check: str, verdict: Verdict) -> None:
        key = (digest, check)
        with self._lock:
            if key not in self._entries:
                self._order.append(key)
            self._entries[key] = verdict
            while len(self._order) > self._max_entries:
                self._entries.pop(self._order.pop(0), None)


class ValidationService:
    def __init__(
        self,
        checkers: Mapping[str, Checker],
        *,
        cache: VerdictCache | None = None,
        max_concurrent: int = 4,
        default_checks: Sequence[str] | None = None,
    ) -> None:
        self._checkers = dict(checkers)
        self._cache = cache if cache is not None else VerdictCache()
        self._slots = threading.BoundedSemaphore(max_concurrent)
        self._default_checks = tuple(default_checks or sorted(self._checkers))

    @property
    def check_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._checkers))

    def validate(
        self,
        claimed_digest: str,
        files: Mapping[str, bytes],
        progress: ProgressSink,
        check_names: Sequence[str] | None = None,
    ) -> ValidationResult:
        digest = verify_digest(files, claimed_digest)
        requested = tuple(check_names) if check_names else self._default_checks
        unknown = [name for name in requested if name not in self._checkers]
        if unknown:
            raise UnknownCheck(", ".join(sorted(unknown)))

        cached = {
            name: verdict
            for name in requested
            if _cacheable(self._checkers[name])
            and (verdict := self._cache.get(digest, name)) is not None
        }
        if len(cached) == len(requested):
            progress("validated", f"cached verdict for {digest}")
            return ValidationResult(
                digest=digest,
                verdicts=tuple(cached[name] for name in requested),
                cached=True,
            )

        tree = Tree(files=dict(files))
        progress("validate", f"{len(tree)} files, checks: {', '.join(requested)}")
        with self._slots:
            verdicts = tuple(
                cached.get(name) or self._run_one(name, digest, tree, progress)
                for name in requested
            )

        for name, verdict in zip(requested, verdicts, strict=True):
            if name not in cached and _cacheable(self._checkers[name]):
                self._cache.put(digest, name, verdict)
        result = ValidationResult(digest=digest, verdicts=verdicts)
        progress(
            "validated" if result.passed else "validation-failed",
            f"{sum(len(v.findings) for v in verdicts)} findings",
        )
        return result

    def _run_one(
        self, name: str, digest: str, tree: Tree, progress: ProgressSink
    ) -> Verdict:
        checker = self._checkers[name]
        try:
            return checker.run(digest, tree, progress)
        except Exception as exc:
            logger.exception("check %s failed", name)
            progress("check-error", f"{name}: {exc}")
            return Verdict(
                passed=False,
                tool=name,
                tool_version="unknown",
                ruleset_digest="unknown",
                findings=(
                    Finding(
                        rule_id=f"{name}/check-error",
                        severity="critical",
                        message=f"check did not complete: {exc}",
                    ),
                ),
            )


def _cacheable(checker: Checker) -> bool:
    """Whether a checker's verdict is a function of the tree alone.

    Read off the checker rather than declared on the protocol, so a checker that
    says nothing keeps the behaviour every checker had before.
    """
    return getattr(checker, "cacheable", True)
