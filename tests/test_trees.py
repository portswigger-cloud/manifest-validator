# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import io
import tarfile

import pytest

from manifest_validator.errors import DigestMismatch, UnknownTree
from manifest_validator.models import Tree
from manifest_validator.trees import (
    InMemoryTreeStore,
    compute_digest,
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
