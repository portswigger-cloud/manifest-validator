# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
from collections.abc import Mapping
from pathlib import PurePosixPath

from manifest_validator.errors import DigestMismatch, MalformedTree

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


def from_tar_gz(
    blob: bytes,
    *,
    max_files: int = 10_000,
    max_total_bytes: int = 256 * 1024 * 1024,
) -> dict[str, bytes]:
    """Read a gzipped tar into a path-to-content mapping.

    Everything here is a rejection rule. The blob arrives from the network and
    is expanded in memory, so the limits are the defence against a small body
    that decompresses to an arbitrary size, and the member checks stop a tree
    from describing paths outside itself.
    """
    files: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isfile():
                    raise MalformedTree(
                        f"{member.name!r} is not a regular file or directory"
                    )
                path = _checked_path(member.name)
                if len(files) >= max_files:
                    raise MalformedTree(f"more than {max_files} files")
                total += member.size
                if total > max_total_bytes:
                    raise MalformedTree(f"expands to more than {max_total_bytes} bytes")
                handle = archive.extractfile(member)
                if handle is None:
                    raise MalformedTree(f"{member.name!r} has no content")
                files[path] = handle.read()
    except (tarfile.TarError, gzip.BadGzipFile, EOFError) as exc:
        raise MalformedTree(f"not a readable gzipped tar: {exc}") from None
    if not files:
        raise MalformedTree("contains no files")
    return files


def _checked_path(name: str) -> str:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or name.startswith("/"):
        raise MalformedTree(f"{name!r} must be relative and without '..'")
    normalised = str(path)
    if normalised in ("", "."):
        raise MalformedTree(f"{name!r} is not a usable path")
    return normalised
