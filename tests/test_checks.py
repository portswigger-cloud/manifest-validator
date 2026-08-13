# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

from manifest_validator.checks import ImagePolicyChecker, StructuralChecker
from manifest_validator.models import Tree

DIGEST = "sha256:0"


def _noop(phase: str, message: str) -> None:
    return None


def _tree(files: dict[str, str]) -> Tree:
    return Tree(files={path: body.encode() for path, body in files.items()})


def test_structural_accepts_a_well_formed_document() -> None:
    tree = _tree(
        {
            "deployment.yaml": (
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: relcoord\n"
            )
        }
    )
    verdict = StructuralChecker().run(DIGEST, tree, _noop)
    assert verdict.passed
    assert verdict.findings == ()


def test_structural_rejects_unparseable_yaml() -> None:
    tree = _tree({"broken.yaml": "a: [unclosed\n"})
    verdict = StructuralChecker().run(DIGEST, tree, _noop)
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "structural/parse"


def test_structural_reports_each_missing_required_field() -> None:
    tree = _tree({"partial.yaml": "kind: Deployment\n"})
    verdict = StructuralChecker().run(DIGEST, tree, _noop)
    rule_ids = {f.rule_id for f in verdict.findings}
    assert rule_ids == {"structural/missing-apiversion", "structural/missing-name"}


def test_structural_ignores_non_manifest_files() -> None:
    tree = _tree({"README.md": "not: [yaml"})
    assert StructuralChecker().run(DIGEST, tree, _noop).passed


def test_structural_skips_empty_documents() -> None:
    tree = _tree(
        {
            "multi.yaml": (
                "---\n---\napiVersion: v1\nkind: Namespace\nmetadata:\n  name: idcat\n"
            )
        }
    )
    assert StructuralChecker().run(DIGEST, tree, _noop).passed


def test_image_policy_accepts_a_pinned_allowed_image() -> None:
    tree = _tree(
        {
            "deployment.yaml": (
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "      - name: app\n        image: public.ecr.aws/q3z6g1h3/relcoord:abc123\n"
            )
        }
    )
    checker = ImagePolicyChecker(allowed_registries=("public.ecr.aws/",))
    assert checker.run(DIGEST, tree, _noop).passed


def test_image_policy_rejects_a_disallowed_registry() -> None:
    tree = _tree(
        {
            "deployment.yaml": (
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "      - name: app\n        image: docker.io/library/nginx:1.27\n"
            )
        }
    )
    checker = ImagePolicyChecker(allowed_registries=("public.ecr.aws/",))
    verdict = checker.run(DIGEST, tree, _noop)
    assert not verdict.passed
    assert verdict.findings[0].rule_id == "image-policy/registry-not-allowed"


def test_image_policy_rejects_an_unpinned_image() -> None:
    tree = _tree(
        {
            "deployment.yaml": (
                "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\n"
                "spec:\n  template:\n    spec:\n      containers:\n"
                "      - name: app\n        image: public.ecr.aws/q3z6g1h3/relcoord\n"
            )
        }
    )
    checker = ImagePolicyChecker(allowed_registries=("public.ecr.aws/",))
    verdict = checker.run(DIGEST, tree, _noop)
    assert {f.rule_id for f in verdict.findings} == {"image-policy/unpinned"}


def test_image_policy_treats_latest_as_unpinned() -> None:
    tree = _tree(
        {
            "pod.yaml": (
                "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n"
                "spec:\n  containers:\n  - name: app\n"
                "    image: public.ecr.aws/q3z6g1h3/relcoord:latest\n"
            )
        }
    )
    checker = ImagePolicyChecker(allowed_registries=("public.ecr.aws/",))
    assert not checker.run(DIGEST, tree, _noop).passed


def test_image_policy_accepts_a_digest_reference() -> None:
    reference = "public.ecr.aws/q3z6g1h3/relcoord@sha256:" + "a" * 64
    tree = _tree(
        {
            "pod.yaml": (
                "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n"
                f"spec:\n  containers:\n  - name: app\n    image: {reference}\n"
            )
        }
    )
    checker = ImagePolicyChecker(allowed_registries=("public.ecr.aws/",))
    assert checker.run(DIGEST, tree, _noop).passed


def test_image_policy_finds_images_nested_in_custom_resources() -> None:
    tree = _tree(
        {
            "xr.yaml": (
                "apiVersion: platform.portswigger.io/v1alpha1\nkind: Thing\n"
                "metadata:\n  name: a\nspec:\n  runner:\n    image: docker.io/x:1\n"
            )
        }
    )
    checker = ImagePolicyChecker(allowed_registries=("public.ecr.aws/",))
    assert not checker.run(DIGEST, tree, _noop).passed
