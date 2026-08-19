# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from manifest_validator.errors import CheckTimeout, MalformedTree
from manifest_validator.models import Tree

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandOutcome:
    exit_code: int
    stdout: str


class CommandRunner(Protocol):
    def run(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
    ) -> CommandOutcome: ...


class SubprocessRunner:
    """Runs a tool as a child process of this service.

    The tool gets the process's own privileges, which is the trade this service
    makes: no scanner here needs egress or a credential, so isolating one in its
    own pod bought nothing but a Job to schedule and an image to pull.
    """

    def run(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
    ) -> CommandOutcome:
        try:
            completed = subprocess.run(  # noqa: S603
                argv,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise CheckTimeout(
                f"{argv[0]} did not finish in {timeout_seconds}s"
            ) from exc
        except OSError as exc:
            raise CheckTimeout(f"could not run {argv[0]}: {exc}") from exc
        return CommandOutcome(
            exit_code=completed.returncode,
            stdout=completed.stdout + completed.stderr,
        )


def write_tree(tree: Tree, destination: Path) -> None:
    """Materialise a tree on disk for a tool that reads files.

    `from_tar_gz` already rejects absolute and traversing paths, but this is
    where a bad path would become a write outside the workspace, so it is
    checked again here rather than trusted from a caller.
    """
    root = destination.resolve()
    for path, content in tree.files.items():
        target = (root / path).resolve()
        if not target.is_relative_to(root):
            raise MalformedTree(f"{path!r} escapes the workspace")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
