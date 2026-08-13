# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import io
import tarfile

import pytest

from manifest_validator.errors import (
    DigestMismatch,
    MalformedTree,
    UnknownTree,
)
from manifest_validator.models import Tree
from manifest_validator.trees import (
    InMemoryTreeStore,
    compute_digest,
    from_tar_gz,
    to_tar,
    verify_digest,
)


def test_digest_is_independent_of_insertion_order() -> None:
    assert compute_digest({"a.yaml": b"1", "b.yaml": b"2"}) == compute_digest(
        {"b.yaml": b"2", "a.yaml": b"1"}
    )


def test_digest_changes_with_content() -> None:
    assert compute_digest({"a.yaml": b"1"}) != compute_digest({"a.yaml": b"2"})


def test_digest_changes_when_a_file_is_renamed() -> None:
    assert compute_digest({"a.yaml": b"1"}) != compute_digest({"b.yaml": b"1"})


def test_digest_framing_resists_boundary_collisions() -> None:
    """Without length framing these two trees would hash the same bytes."""
    assert compute_digest({"ab": b"c"}) != compute_digest({"a": b"bc"})


def test_empty_tree_has_a_stable_digest() -> None:
    assert compute_digest({}).startswith("sha256:")


def test_verify_digest_rejects_a_mismatch() -> None:
    with pytest.raises(DigestMismatch):
        verify_digest({"a.yaml": b"1"}, "sha256:" + "0" * 64)


def test_verify_digest_returns_the_digest_on_success() -> None:
    files = {"a.yaml": b"1"}
    expected = compute_digest(files)
    assert verify_digest(files, expected) == expected


def test_tar_round_trips_and_is_deterministic() -> None:
    tree = Tree(files={"b.yaml": b"two", "a.yaml": b"one"})
    first = to_tar(tree)
    assert first == to_tar(Tree(files={"a.yaml": b"one", "b.yaml": b"two"}))
    with tarfile.open(fileobj=io.BytesIO(first)) as archive:
        assert archive.getnames() == ["a.yaml", "b.yaml"]
        member = archive.extractfile("a.yaml")
        assert member is not None
        assert member.read() == b"one"


def test_store_discards_trees() -> None:
    store = InMemoryTreeStore()
    tree = Tree(files={"a.yaml": b"1"})
    store.put("sha256:x", tree)
    assert store.get("sha256:x") is tree
    store.discard("sha256:x")
    with pytest.raises(UnknownTree):
        store.get("sha256:x")


def _blob(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        _add_all(archive, files)
    return buffer.getvalue()


def _uncompressed_blob(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        _add_all(archive, files)
    return buffer.getvalue()


def _add_all(archive: tarfile.TarFile, files: dict[str, bytes]) -> None:
    for path, content in files.items():
        info = tarfile.TarInfo(name=path)
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))


def test_from_tar_gz_round_trips_a_tree() -> None:
    files = {"a.yaml": b"one", "nested/b.yaml": b"two"}
    assert from_tar_gz(_blob(files)) == files


def test_from_tar_gz_preserves_the_digest_across_the_wire() -> None:
    files = {"a.yaml": b"one", "b/c.yaml": b"two"}
    assert compute_digest(from_tar_gz(_blob(files))) == compute_digest(files)


def test_from_tar_gz_rejects_a_body_that_is_not_gzip() -> None:
    with pytest.raises(MalformedTree, match="gzipped tar"):
        from_tar_gz(b"plain bytes")


def test_from_tar_gz_rejects_an_uncompressed_tar() -> None:
    with pytest.raises(MalformedTree, match="gzipped tar"):
        from_tar_gz(_uncompressed_blob({"a.yaml": b"one"}))


def test_from_tar_gz_rejects_an_empty_archive() -> None:
    with pytest.raises(MalformedTree, match="no files"):
        from_tar_gz(_blob({}))


def test_from_tar_gz_rejects_an_absolute_member() -> None:
    with pytest.raises(MalformedTree, match="relative"):
        from_tar_gz(_blob({"/etc/passwd": b"x"}))


def test_from_tar_gz_rejects_a_traversing_member() -> None:
    with pytest.raises(MalformedTree, match="relative"):
        from_tar_gz(_blob({"../escape.yaml": b"x"}))


def test_from_tar_gz_rejects_a_nested_traversal() -> None:
    with pytest.raises(MalformedTree, match="relative"):
        from_tar_gz(_blob({"a/../../escape.yaml": b"x"}))


def test_from_tar_gz_rejects_a_symlink() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo(name="link.yaml")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        archive.addfile(info)
    with pytest.raises(MalformedTree, match="not a regular file"):
        from_tar_gz(buffer.getvalue())


def test_from_tar_gz_enforces_a_file_count_limit() -> None:
    blob = _blob({f"f{i}.yaml": b"x" for i in range(10)})
    with pytest.raises(MalformedTree, match="more than 4 files"):
        from_tar_gz(blob, max_files=4)


def test_from_tar_gz_enforces_a_total_size_limit() -> None:
    """A small blob must not be allowed to expand without bound."""
    blob = _blob({"big.yaml": b"\0" * 100_000})
    assert len(blob) < 1000
    with pytest.raises(MalformedTree, match="more than 1024 bytes"):
        from_tar_gz(blob, max_total_bytes=1024)


def test_from_tar_gz_ignores_directory_members() -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        directory = tarfile.TarInfo(name="nested")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        info = tarfile.TarInfo(name="nested/a.yaml")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"one"))
    assert from_tar_gz(buffer.getvalue()) == {"nested/a.yaml": b"one"}
