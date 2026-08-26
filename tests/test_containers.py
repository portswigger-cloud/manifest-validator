# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

from pathlib import Path

from manifest_validator.commands import CommandOutcome
from manifest_validator.containers import CraneCrunRunner, bundle_spec

IMAGE = "public.ecr.aws/portswigger-platform/idcat:1.0"


class RecordingRunner:
    def __init__(self, exit_codes: dict[str, int] | None = None) -> None:
        self.argvs: list[tuple[str, ...]] = []
        self._exit_codes = exit_codes or {}

    def run(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
    ) -> CommandOutcome:
        self.argvs.append(argv)
        exit_code = self._exit_codes.get(argv[0], 0)
        if argv[0] == "crane" and exit_code == 0:
            _write_tarball(Path(argv[-1]))
        return CommandOutcome(exit_code=exit_code, stdout=f"{argv[0]} ran")


def _run(runner: object, tmp_path: Path) -> object:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "idcat.toml").write_text("a = 1\n")
    return CraneCrunRunner(command_runner=runner).run(  # ty: ignore
        IMAGE, config_dir, "/config", timeout_seconds=30
    )


def test_the_image_is_exported_before_it_is_run(tmp_path: Path) -> None:
    runner = RecordingRunner()

    _run(runner, tmp_path)

    assert [argv[0] for argv in runner.argvs] == ["crane", "crun"]
    export = runner.argvs[0]
    assert export[:2] == ("crane", "export")
    assert IMAGE in export


def test_the_exit_code_of_the_container_is_what_comes_back(tmp_path: Path) -> None:
    runner = RecordingRunner(exit_codes={"crun": 3})

    outcome = _run(runner, tmp_path)

    assert outcome.exit_code == 3  # ty: ignore
    assert "crun ran" in outcome.output  # ty: ignore


def test_an_image_that_will_not_export_never_reaches_crun(tmp_path: Path) -> None:
    runner = RecordingRunner(exit_codes={"crane": 1})

    outcome = _run(runner, tmp_path)

    assert [argv[0] for argv in runner.argvs] == ["crane"]
    assert outcome.exit_code != 0  # ty: ignore
    assert "could not be pulled" in outcome.output  # ty: ignore


def test_the_container_runs_the_fixed_validate_argv() -> None:
    spec = bundle_spec(IMAGE, "/config", ("--validate-config",))

    assert spec["process"]["args"] == ["--validate-config"]


def test_the_container_gets_no_network() -> None:
    spec = bundle_spec(IMAGE, "/config", ("--validate-config",))

    namespaces = {entry["type"] for entry in spec["linux"]["namespaces"]}
    assert "network" in namespaces
    assert all("path" not in entry for entry in spec["linux"]["namespaces"])


def test_the_config_is_mounted_read_only_where_the_app_expects_it() -> None:
    spec = bundle_spec(IMAGE, "/etc/thing", ("--validate-config",))

    (mount,) = [m for m in spec["mounts"] if m["destination"] == "/etc/thing"]
    assert "ro" in mount["options"]
    assert mount["source"] == "/config"


def test_the_container_keeps_no_capabilities_and_cannot_gain_privilege() -> None:
    spec = bundle_spec(IMAGE, "/config", ("--validate-config",))

    capabilities = spec["process"]["capabilities"]
    assert all(capabilities[key] == [] for key in capabilities)
    assert spec["process"]["noNewPrivileges"] is True
    assert spec["root"]["readonly"] is True


def test_the_container_does_not_run_as_root() -> None:
    spec = bundle_spec(IMAGE, "/config", ("--validate-config",))

    assert spec["process"]["user"]["uid"] != 0


class ExportingRunner:
    """Answers `crane export` the way crane does: by writing a tarball."""

    def __init__(self) -> None:
        self.argvs: list[tuple[str, ...]] = []
        self.rootfs_at_run: list[list[str]] = []

    def run(
        self, argv: tuple[str, ...], cwd: Path, timeout_seconds: int
    ) -> CommandOutcome:
        self.argvs.append(argv)
        if argv[0] == "crane":
            _write_tarball(Path(argv[-1]))
        else:
            self.rootfs_at_run.append(
                sorted(path.name for path in (cwd / "rootfs").iterdir())
            )
        return CommandOutcome(exit_code=0, stdout="")


def _write_tarball(destination: Path) -> None:
    import io
    import tarfile

    with tarfile.open(destination, "w") as archive:
        payload = b"#!/bin/sh\n"
        info = tarfile.TarInfo("usr/bin/idcat")
        info.size = len(payload)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(payload))


def test_the_exported_filesystem_is_unpacked_before_the_container_runs(
    tmp_path: Path,
) -> None:
    runner = ExportingRunner()

    _run(runner, tmp_path)

    assert runner.rootfs_at_run == [["usr"]], (
        "crun ran over an empty rootfs: nothing unpacked the exported image"
    )
