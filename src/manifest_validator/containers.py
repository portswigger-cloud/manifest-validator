# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
"""Runs an application image over a directory of config.

Two tools rather than a container engine: `crane` fetches the image's flattened
filesystem straight from the registry, and `crun` execs a process in it. There is
no daemon in this pod and no reason to want one.

The isolation lives in the bundle spec below. Unpacking an image and exec'ing its
entrypoint directly would run a third party's code in this service's own
namespaces, with its filesystem and its network — which is exactly what a fixed
argv and a registry allow-list cannot protect against.
"""

from __future__ import annotations

import json
import logging
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from manifest_validator.appconfig import VALIDATE_ARGV, ContainerOutcome
from manifest_validator.commands import CommandRunner, SubprocessRunner

logger = logging.getLogger(__name__)

CRANE = "crane"
CRUN = "crun"

# Where the config lands inside the bundle, before crun binds it over the path
# the application actually reads from.
BUNDLE_CONFIG_SOURCE = "/config"

# Not root, and not a uid the image is likely to have a passwd entry for: the
# process only has to read files this service wrote.
RUN_AS_UID = 65534


def bundle_spec(image: str, mount_path: str, argv: tuple[str, ...]) -> dict[str, Any]:
    """The OCI runtime spec crun is handed.

    Every namespace is unshared with no `path`, so nothing is joined: an entry
    with a path would put the container in *our* namespace rather than a new one.
    """
    return {
        "ociVersion": "1.0.2",
        "process": {
            "terminal": False,
            "user": {"uid": RUN_AS_UID, "gid": RUN_AS_UID},
            "args": list(argv),
            "env": ["PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/"],
            "cwd": "/",
            "noNewPrivileges": True,
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
        },
        "root": {"path": "rootfs", "readonly": True},
        "hostname": "manifest-validator",
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {
                "destination": "/tmp",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", "mode=1777", "size=16m"],
            },
            {
                "destination": mount_path,
                "type": "bind",
                "source": BUNDLE_CONFIG_SOURCE,
                "options": ["rbind", "ro", "nosuid", "nodev", "noexec"],
            },
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
                {"type": "network"},
            ],
            "maskedPaths": ["/proc/kcore", "/sys/firmware"],
            "readonlyPaths": ["/proc/sys"],
        },
        "annotations": {"manifest-validator.portswigger.com/image": image},
    }


@dataclass(frozen=True)
class CraneCrunRunner:
    """Fetch an image, then run it with no network and a read-only config mount.

    A tool run this way still runs with this service's privileges on the host
    side: crane's egress and crun's own execution are ours. What the bundle
    limits is what the *application* can reach once started.
    """

    command_runner: CommandRunner = field(default_factory=SubprocessRunner)
    argv: tuple[str, ...] = VALIDATE_ARGV

    def run(
        self, image: str, config_dir: Path, mount_path: str, timeout_seconds: int
    ) -> ContainerOutcome:
        with tempfile.TemporaryDirectory(prefix="manifest-validator-bundle-") as work:
            bundle = Path(work)
            rootfs = bundle / "rootfs"
            rootfs.mkdir()
            tarball = bundle / "image.tar"
            export = self.command_runner.run(
                (CRANE, "export", image, str(tarball)), bundle, timeout_seconds
            )
            if export.exit_code != 0:
                return ContainerOutcome(
                    exit_code=export.exit_code,
                    output=f"{image} could not be pulled: {export.stdout}",
                )
            try:
                _unpack(tarball, rootfs)
            except (OSError, tarfile.TarError) as exc:
                return ContainerOutcome(
                    exit_code=1,
                    output=f"{image} could not be pulled: {exc}",
                )
            spec = bundle_spec(image, mount_path, self.argv)
            (bundle / "config.json").write_text(json.dumps(spec))
            outcome = self.command_runner.run(
                (CRUN, "run", "--bundle", str(bundle), _container_id(image)),
                bundle,
                timeout_seconds,
            )
            return ContainerOutcome(exit_code=outcome.exit_code, output=outcome.stdout)


def _unpack(tarball: Path, rootfs: Path) -> None:
    """Unpack the exported filesystem.

    `filter="data"` because the tar comes from an image the tree named: it
    refuses absolute paths, `..`, links out of the destination and device nodes,
    none of which an application's filesystem needs to be validated.
    """
    with tarfile.open(tarball) as archive:
        archive.extractall(rootfs, filter="data")
    tarball.unlink()


def _container_id(image: str) -> str:
    return (
        "validate-"
        + "".join(character if character.isalnum() else "-" for character in image)[
            -48:
        ]
    )
