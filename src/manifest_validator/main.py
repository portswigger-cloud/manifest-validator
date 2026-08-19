# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import click
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from manifest_validator.app import create_app
from manifest_validator.checks import Checker, ImagePolicyChecker, StructuralChecker
from manifest_validator.commands import SubprocessRunner
from manifest_validator.config import CheckConfig, Settings
from manifest_validator.kics import KicsChecker
from manifest_validator.service import ValidationService

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path("/config/manifest-validator.toml")


def build_checkers(settings: Settings) -> dict[str, Checker]:
    return {check.name: _build_checker(check) for check in settings.checks}


def _build_checker(check: CheckConfig) -> Checker:
    if check.kind == "structural":
        return StructuralChecker()
    if check.kind == "image-policy":
        return ImagePolicyChecker(
            allowed_registries=check.allowed_registries,
            require_pinned=check.require_pinned,
        )
    return KicsChecker(
        check_name=check.name,
        runner=SubprocessRunner(),
        types=check.types,
        exclude_severities=check.exclude_severities,
        timeout_seconds=check.timeout_seconds,
    )


@click.command()
@click.option(
    "--config-path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=DEFAULT_CONFIG_PATH,
    show_default=True,
)
def main(config_path: Path) -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    settings = Settings.from_path(config_path)

    service = ValidationService(
        build_checkers(settings),
        max_concurrent=settings.max_concurrent,
        default_checks=settings.default_check_names,
    )
    app = create_app(service)

    hypercorn = HypercornConfig()
    hypercorn.bind = [settings.bind_address]
    hypercorn.accesslog = "-"
    logger.info(
        "listening on %s with checks: %s",
        settings.bind_address,
        ", ".join(service.check_names),
    )
    asyncio.run(serve(app, hypercorn))  # ty: ignore


if __name__ == "__main__":
    main()
