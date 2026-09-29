# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import click
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from manifest_validator.app import create_app
from manifest_validator.checks import Checker, ImagePolicyChecker, StructuralChecker
from manifest_validator.commands import SubprocessRunner
from manifest_validator.config import CheckConfig, Settings
from manifest_validator.dynamodb_store import DynamoDBScanStore
from manifest_validator.kics import KicsChecker, KicsScanner
from manifest_validator.scan_cache import FileScanCache, ScanStore
from manifest_validator.service import ValidationService

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path("/config/manifest-validator.toml")

# Set by the Dockerfile from the same argument that picks the KICS image.
KICS_VERSION_ENV = "KICS_VERSION"


def build_checkers(
    settings: Settings, kics_version: str | None = None
) -> dict[str, Checker]:
    store = (
        DynamoDBScanStore.connect(settings.scan_cache)
        if settings.scan_cache is not None
        else None
    )
    if kics_version is None and any(c.kind == "kics" for c in settings.checks):
        logger.warning(
            "%s is unset, so KICS findings are not remembered at all",
            KICS_VERSION_ENV,
        )
    return {
        check.name: _build_checker(check, store, kics_version)
        for check in settings.checks
    }


def _build_checker(
    check: CheckConfig, store: ScanStore | None, kics_version: str | None
) -> Checker:
    if check.kind == "structural":
        return StructuralChecker()
    if check.kind == "image-policy":
        return ImagePolicyChecker(
            allowed_registries=check.allowed_registries,
            require_pinned=check.require_pinned,
        )
    return KicsChecker(
        scanner=KicsScanner(
            check_name=check.name,
            runner=SubprocessRunner(),
            types=check.types,
            exclude_severities=check.exclude_severities,
            exclude_queries=check.exclude_queries,
            timeout_seconds=check.timeout_seconds,
            version=kics_version,
        ),
        exceptions=check.exceptions,
        cache=FileScanCache(store),
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
        build_checkers(settings, os.environ.get(KICS_VERSION_ENV) or None),
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
