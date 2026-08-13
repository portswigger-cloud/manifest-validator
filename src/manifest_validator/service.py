# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import logging
import threading
from collections.abc import Mapping, Sequence

from manifest_validator.checks import Checker, ProgressSink
from manifest_validator.errors import UnknownCheck
from manifest_validator.models import Finding, Tree, ValidationResult, Verdict
from manifest_validator.trees import TreeStore, verify_digest

logger = logging.getLogger(__name__)


class VerdictCache:
    """Dedupes repeat validations of byte-identical trees.

    Keyed on content digest plus the set of checks, so a verdict is valid
    exactly as long as both are unchanged. Machine-driven image bumps
    regenerate identical trees often enough that this is load-bearing, not an
    optimisation.
    """

    def __init__(self, max_entries: int = 256) -> None:
        self._entries: dict[tuple[str, tuple[str, ...]], tuple[Verdict, ...]] = {}
        self._order: list[tuple[str, tuple[str, ...]]] = []
        self._max_entries = max_entries
        self._lock = threading.Lock()

    def get(self, digest: str, checks: tuple[str, ...]) -> tuple[Verdict, ...] | None:
        with self._lock:
            return self._entries.get((digest, checks))

    def put(
        self, digest: str, checks: tuple[str, ...], verdicts: tuple[Verdict, ...]
    ) -> None:
        key = (digest, checks)
        with self._lock:
            if key not in self._entries:
                self._order.append(key)
            self._entries[key] = verdicts
            while len(self._order) > self._max_entries:
                self._entries.pop(self._order.pop(0), None)


class ValidationService:
    def __init__(
        self,
        checkers: Mapping[str, Checker],
        tree_store: TreeStore,
        *,
        cache: VerdictCache | None = None,
        max_concurrent: int = 4,
        default_checks: Sequence[str] | None = None,
    ) -> None:
        self._checkers = dict(checkers)
        self._tree_store = tree_store
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

        cache_key = tuple(sorted(requested))
        cached = self._cache.get(digest, cache_key)
        if cached is not None:
            progress("validated", f"cached verdict for {digest}")
            return ValidationResult(digest=digest, verdicts=cached, cached=True)

        tree = Tree(files=dict(files))
        self._tree_store.put(digest, tree)
        progress("validate", f"{len(tree)} files, checks: {', '.join(requested)}")
        try:
            with self._slots:
                verdicts = tuple(
                    self._run_one(name, digest, tree, progress) for name in requested
                )
        finally:
            self._tree_store.discard(digest)

        self._cache.put(digest, cache_key, verdicts)
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
