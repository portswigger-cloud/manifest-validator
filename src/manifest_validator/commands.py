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
    """A tool runs with this service's privileges, which is only acceptable
    while every tool is offline and unauthenticated."""

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
    """`from_tar_gz` rejects these paths already, but this is where one would
    become a write outside the workspace, so it is not taken on trust."""
    root = destination.resolve()
    for path, content in tree.files.items():
        target = (root / path).resolve()
        if not target.is_relative_to(root):
            raise MalformedTree(f"{path!r} escapes the workspace")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
