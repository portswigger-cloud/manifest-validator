# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import hashlib
import io
import tarfile
import threading
from collections.abc import Mapping
from typing import Protocol

from manifest_validator.errors import DigestMismatch, UnknownTree
from manifest_validator.models import Tree

DIGEST_PREFIX = b"manifest-validator-tree-v1\x00"


def compute_digest(files: Mapping[str, bytes]) -> str:
    """Digest the tree's content, independent of transport or file order.

    Framed with explicit lengths so that no combination of path and content can
    collide with a different tree by concatenating differently. relcoord must
    implement this byte-for-byte; see README.
    """
    digest = hashlib.sha256()
    digest.update(DIGEST_PREFIX)
    for path in sorted(files):
        content = files[path]
        encoded_path = path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def verify_digest(files: Mapping[str, bytes], claimed: str) -> str:
    actual = compute_digest(files)
    if actual != claimed:
        raise DigestMismatch(f"claimed {claimed}, computed {actual}")
    return actual


def to_tar(tree: Tree) -> bytes:
    """Render a tree as a deterministic uncompressed tar for a Job to pull."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(tree.files):
            content = tree.files[path]
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            info.mtime = 0
            info.mode = 0o444
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


class TreeStore(Protocol):
    def put(self, digest: str, tree: Tree) -> None: ...

    def get(self, digest: str) -> Tree: ...

    def discard(self, digest: str) -> None: ...


class InMemoryTreeStore:
    """Holds trees for the lifetime of an in-flight validation.

    A restart mid-scan loses the tree and the Job pulling it fails; the design
    calls for S3 when that durability is wanted.
    """

    def __init__(self) -> None:
        self._trees: dict[str, Tree] = {}
        self._lock = threading.Lock()

    def put(self, digest: str, tree: Tree) -> None:
        with self._lock:
            self._trees[digest] = tree

    def get(self, digest: str) -> Tree:
        with self._lock:
            try:
                return self._trees[digest]
            except KeyError:
                raise UnknownTree(digest) from None

    def discard(self, digest: str) -> None:
        with self._lock:
            self._trees.pop(digest, None)
