# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Protocol

from manifest_validator.checks import ProgressSink
from manifest_validator.models import Tree

logger = logging.getLogger(__name__)


class Attributed(Protocol):
    """A result that names the file it is about, or None if it is about none."""

    @property
    def file(self) -> str | None: ...


@dataclass(frozen=True)
class Scan[R: Attributed]:
    """What a scanner reported, before any policy decides what fails."""

    tool_version: str
    findings: tuple[R, ...]
    reused_files: int = 0
    rememberable: bool = True
    """False when the scan ran but not as the scanner's identity says it would."""


class Scanner[R: Attributed](Protocol):
    """A tool whose findings for a file depend on that file alone.

    Only such a tool may sit behind `FileScanCache`: a partial scan stitched
    together with remembered findings equals a full scan only when no finding
    depends on another file.
    """

    @property
    def cache_identity(self) -> str | None:
        """Everything other than the file that decides its findings.

        The tool version, its ruleset selection and the encoding below. None
        when that cannot be known before scanning, which keeps results out of
        any store that outlives this process.
        """
        ...

    def scan(self, tree: Tree, progress: ProgressSink) -> Scan[R]: ...

    def encode(self, result: R) -> dict[str, Any]: ...

    def decode(self, data: dict[str, Any]) -> R: ...


class ScanStore(Protocol):
    """Where remembered findings are kept, as encoded text by key.

    Anything that can write here can make a finding disappear, so only this
    service may. A store that cannot be reached must behave as empty rather
    than raise: losing the cache costs a scan, failing a check costs a deploy.
    """

    def get_many(self, keys: Collection[str]) -> dict[str, str]: ...

    def put_many(self, entries: Mapping[str, str]) -> None: ...


class MemoryScanStore:
    """A `ScanStore` for one process, for when no shared one is configured."""

    def __init__(self, max_entries: int = 20_000) -> None:
        self._entries: OrderedDict[str, str] = OrderedDict()
        self._max_entries = max_entries
        self._lock = threading.Lock()

    def get_many(self, keys: Collection[str]) -> dict[str, str]:
        found: dict[str, str] = {}
        with self._lock:
            for key in keys:
                if key in self._entries:
                    self._entries.move_to_end(key)
                    found[key] = self._entries[key]
        return found

    def put_many(self, entries: Mapping[str, str]) -> None:
        with self._lock:
            for key, entry in entries.items():
                self._entries[key] = entry
                self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)


@dataclass(frozen=True)
class _Entry[R: Attributed]:
    tool_version: str
    findings: tuple[R, ...]


class FileScanCache[R: Attributed]:
    """Remembers a scanner's findings per file, so only changed files are scanned.

    Keyed on path as well as content: a scanner may fold the path into a
    finding — a KICS similarity id covers it — so the same bytes elsewhere are
    a different result. Keyed on the scanner's identity too, so a new tool
    version or ruleset starts from nothing rather than reusing its predecessor.
    A scanner with no identity is not cached at all.

    Nothing is remembered from a scan with a finding that names no file in the
    tree. That is how a failed scan reports itself, and a failure remembered as
    a file's result would pass that file from then on.
    """

    def __init__(self, store: ScanStore | None = None) -> None:
        self._store = store if store is not None else MemoryScanStore()

    def scan(self, scanner: Scanner[R], tree: Tree, progress: ProgressSink) -> Scan[R]:
        identity = scanner.cache_identity
        if identity is None:
            return scanner.scan(tree, progress)

        keys = {
            path: _key(identity, path, content) for path, content in tree.files.items()
        }
        remembered = self._recall(scanner, keys.values())
        unscanned = {
            path: tree.files[path]
            for path, key in keys.items()
            if key not in remembered
        }
        per_file = {
            path: remembered[key].findings
            for path, key in keys.items()
            if key in remembered
        }
        reused = len(per_file)

        if unscanned or not remembered:
            fresh = scanner.scan(Tree(files=unscanned), progress)
            attributed = _attribute(fresh.findings, unscanned)
            if attributed is None:
                return Scan(
                    tool_version=fresh.tool_version,
                    findings=_in_path_order(per_file) + fresh.findings,
                    reused_files=reused,
                )
            if fresh.rememberable:
                self._store.put_many(
                    {
                        keys[path]: _encode(
                            scanner, _Entry(fresh.tool_version, findings)
                        )
                        for path, findings in attributed.items()
                    }
                )
            per_file.update(attributed)
            tool_version = fresh.tool_version
        else:
            # Entries share an identity, which names the tool version.
            tool_version = next(iter(remembered.values())).tool_version

        return Scan(
            tool_version=tool_version,
            findings=_in_path_order(per_file),
            reused_files=reused,
        )

    def _recall(
        self, scanner: Scanner[R], keys: Collection[str]
    ) -> dict[str, _Entry[R]]:
        found: dict[str, _Entry[R]] = {}
        for key, raw in self._store.get_many(keys).items():
            entry = _decode(scanner, raw)
            if entry is not None:
                found[key] = entry
        return found


def resolve_path(reported: str | None, paths: Collection[str]) -> str | None:
    """Map a path as a tool reported it back onto a tree path.

    KICS reports relative to its working directory, but has been seen to prefix
    the result with `./` or to climb out of the tree and back in, so an exact
    match is not enough.
    """
    if not reported:
        return None
    parts = [p for p in PurePosixPath(reported).parts if p not in (".", "..")]
    if not parts:
        return None
    candidate = "/".join(parts)
    if candidate in paths:
        return candidate
    matches = [path for path in paths if candidate.endswith(path)]
    return matches[0] if len(matches) == 1 else None


def _key(identity: str, path: str, content: bytes) -> str:
    digest = hashlib.sha256()
    for part in (identity.encode(), path.encode(), hashlib.sha256(content).digest()):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def _encode[R: Attributed](scanner: Scanner[R], entry: _Entry[R]) -> str:
    return json.dumps(
        {
            "tool_version": entry.tool_version,
            "findings": [scanner.encode(f) for f in entry.findings],
        }
    )


def _decode[R: Attributed](scanner: Scanner[R], raw: str) -> _Entry[R] | None:
    try:
        data = json.loads(raw)
        return _Entry(
            tool_version=str(data["tool_version"]),
            findings=tuple(scanner.decode(f) for f in data["findings"]),
        )
    except (ValueError, KeyError, TypeError) as exc:
        logger.warning("ignoring an unreadable cached scan: %s", exc)
        return None


def _attribute[R: Attributed](
    findings: tuple[R, ...], paths: Collection[str]
) -> dict[str, tuple[R, ...]] | None:
    by_path: dict[str, list[R]] = {path: [] for path in paths}
    for finding in findings:
        path = resolve_path(finding.file, paths)
        if path is None:
            return None
        by_path[path].append(finding)
    return {path: tuple(found) for path, found in by_path.items()}


def _in_path_order[R: Attributed](
    per_file: Mapping[str, tuple[R, ...]],
) -> tuple[R, ...]:
    return tuple(finding for path in sorted(per_file) for finding in per_file[path])
