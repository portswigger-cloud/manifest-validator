# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any

from manifest_validator.models import Tree
from manifest_validator.scan_cache import (
    FileScanCache,
    MemoryScanStore,
    Scan,
    resolve_path,
)


@dataclass(frozen=True)
class Result:
    file: str | None
    rule: str = "bad"


class Codec:
    cache_identity: str | None = "stub-v1"

    def encode(self, result: Result) -> dict[str, Any]:
        return {"file": result.file, "rule": result.rule}

    def decode(self, data: dict[str, Any]) -> Result:
        return Result(data["file"], data["rule"])


class FlagsBadFiles(Codec):
    """A per-file scanner: one result for every file whose content says `bad`."""

    def __init__(
        self,
        version: str = "v1",
        reported_prefix: str = "",
        identity: str | None = "stub-v1",
        rememberable: bool = True,
    ) -> None:
        self.version = version
        self.reported_prefix = reported_prefix
        self.cache_identity = identity
        self.rememberable = rememberable
        self.scanned: list[list[str]] = []

    def scan(self, tree: Tree, progress: object) -> Scan[Result]:
        self.scanned.append(sorted(tree.files))
        return Scan(
            tool_version=self.version,
            findings=tuple(
                Result(self.reported_prefix + path)
                for path, content in sorted(tree.files.items())
                if b"bad" in content
            ),
            rememberable=self.rememberable,
        )


class FailsToRun(Codec):
    def __init__(self) -> None:
        self.calls = 0

    def scan(self, tree: Tree, progress: object) -> Scan[Result]:
        self.calls += 1
        return Scan(tool_version="unknown", findings=(Result(None, "crashed"),))


def _noop(phase: str, message: str) -> None:
    return None


TREE = Tree(files={"a.yaml": b"bad", "b.yaml": b"good", "c/d.yaml": b"bad"})


def test_an_unchanged_file_is_not_rescanned() -> None:
    cache, scanner = FileScanCache[Result](), FlagsBadFiles()
    cache.scan(scanner, TREE, _noop)
    changed = Tree(files={**TREE.files, "b.yaml": b"bad now"})
    scan = cache.scan(scanner, changed, _noop)
    assert scanner.scanned[-1] == ["b.yaml"]
    assert scan.reused_files == 2


def test_a_partial_scan_reports_what_a_full_scan_would() -> None:
    cache, scanner = FileScanCache[Result](), FlagsBadFiles()
    cache.scan(scanner, TREE, _noop)
    changed = Tree(files={**TREE.files, "b.yaml": b"bad now", "a.yaml": b"fixed"})
    partial = cache.scan(scanner, changed, _noop)
    full = FileScanCache[Result]().scan(FlagsBadFiles(), changed, _noop)
    assert partial.findings == full.findings
    assert partial.tool_version == full.tool_version


def test_an_unchanged_tree_runs_no_scanner_and_keeps_its_version() -> None:
    cache, scanner = FileScanCache[Result](), FlagsBadFiles(version="v9")
    first = cache.scan(scanner, TREE, _noop)
    again = cache.scan(scanner, TREE, _noop)
    assert len(scanner.scanned) == 1
    assert again.findings == first.findings
    assert again.tool_version == "v9"
    assert again.reused_files == len(TREE)


def test_a_file_that_moves_is_scanned_again() -> None:
    """A finding may carry its path, so the same bytes elsewhere are new."""
    cache, scanner = FileScanCache[Result](), FlagsBadFiles()
    cache.scan(scanner, TREE, _noop)
    cache.scan(scanner, Tree(files={"moved/a.yaml": b"bad"}), _noop)
    assert scanner.scanned[-1] == ["moved/a.yaml"]


def test_a_failed_scan_is_reported_and_not_remembered() -> None:
    cache, scanner = FileScanCache[Result](), FailsToRun()
    scan = cache.scan(scanner, TREE, _noop)
    assert [r.rule for r in scan.findings] == ["crashed"]
    cache.scan(scanner, TREE, _noop)
    assert scanner.calls == 2


def test_a_failed_scan_still_reports_the_files_it_did_not_need_to_scan() -> None:
    cache = FileScanCache[Result]()
    cache.scan(FlagsBadFiles(), TREE, _noop)
    changed = Tree(files={**TREE.files, "b.yaml": b"changed"})
    scan = cache.scan(FailsToRun(), changed, _noop)
    assert [(r.file, r.rule) for r in scan.findings] == [
        ("a.yaml", "bad"),
        ("c/d.yaml", "bad"),
        (None, "crashed"),
    ]


def test_a_path_the_scanner_decorates_is_still_attributed() -> None:
    cache, scanner = FileScanCache[Result](), FlagsBadFiles(reported_prefix="./")
    cache.scan(scanner, TREE, _noop)
    cache.scan(scanner, TREE, _noop)
    assert len(scanner.scanned) == 1


def test_an_empty_tree_is_still_put_to_the_scanner() -> None:
    cache, scanner = FileScanCache[Result](), FlagsBadFiles()
    cache.scan(scanner, Tree(), _noop)
    assert scanner.scanned == [[]]


def test_the_least_recently_seen_file_is_forgotten_first() -> None:
    cache = FileScanCache[Result](MemoryScanStore(max_entries=2))
    scanner = FlagsBadFiles()
    cache.scan(scanner, Tree(files={"a": b"1", "b": b"2"}), _noop)
    cache.scan(scanner, Tree(files={"a": b"1"}), _noop)
    cache.scan(scanner, Tree(files={"c": b"3"}), _noop)
    cache.scan(scanner, Tree(files={"a": b"1", "b": b"2"}), _noop)
    assert scanner.scanned[-1] == ["b"]


def test_resolve_path_refuses_an_ambiguous_suffix() -> None:
    assert resolve_path("x/a.yaml", {"one/x/a.yaml", "two/x/a.yaml"}) is None
    assert resolve_path("../tree/x/a.yaml", {"x/a.yaml"}) == "x/a.yaml"


class DictStore:
    def __init__(self) -> None:
        self.items: dict[str, str] = {}
        self.reads = 0

    def get_many(self, keys: Collection[str]) -> dict[str, str]:
        self.reads += 1
        return {k: self.items[k] for k in keys if k in self.items}

    def put_many(self, entries: Mapping[str, str]) -> None:
        self.items.update(entries)


def test_a_restarted_process_reuses_what_the_store_remembers() -> None:
    store = DictStore()
    first = FileScanCache[Result](store).scan(FlagsBadFiles(), TREE, _noop)
    scanner = FlagsBadFiles()
    again = FileScanCache[Result](store).scan(scanner, TREE, _noop)
    assert scanner.scanned == []
    assert again.findings == first.findings
    assert again.tool_version == first.tool_version


def test_a_new_scanner_identity_starts_from_nothing() -> None:
    store = DictStore()
    FileScanCache[Result](store).scan(FlagsBadFiles(identity="v1"), TREE, _noop)
    upgraded = FlagsBadFiles(identity="v2")
    FileScanCache[Result](store).scan(upgraded, TREE, _noop)
    assert upgraded.scanned == [sorted(TREE.files)]


def test_a_scanner_without_an_identity_is_never_cached() -> None:
    store = DictStore()
    cache, scanner = FileScanCache[Result](store), FlagsBadFiles(identity=None)
    cache.scan(scanner, TREE, _noop)
    cache.scan(scanner, TREE, _noop)
    assert len(scanner.scanned) == 2
    assert store.items == {}
    assert store.reads == 0


def test_an_unreadable_stored_entry_is_rescanned() -> None:
    store = DictStore()
    FileScanCache[Result](store).scan(FlagsBadFiles(), TREE, _noop)
    store.items = dict.fromkeys(store.items, "not json")
    scanner = FlagsBadFiles()
    scan = FileScanCache[Result](store).scan(scanner, TREE, _noop)
    assert scanner.scanned == [sorted(TREE.files)]
    assert len(scan.findings) == 2


def test_a_scan_that_is_not_rememberable_is_reported_but_not_stored() -> None:
    store = DictStore()
    cache = FileScanCache[Result](store)
    scan = cache.scan(FlagsBadFiles(rememberable=False), TREE, _noop)
    assert [r.file for r in scan.findings] == ["a.yaml", "c/d.yaml"]
    assert store.items == {}
    scanner = FlagsBadFiles()
    cache.scan(scanner, TREE, _noop)
    assert scanner.scanned == [sorted(TREE.files)]
