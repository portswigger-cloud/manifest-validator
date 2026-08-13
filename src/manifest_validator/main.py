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
from manifest_validator.auth import TokenValidator
from manifest_validator.checks import Checker, ImagePolicyChecker, StructuralChecker
from manifest_validator.config import CheckConfig, Settings
from manifest_validator.jobs import JobChecker, JobRunner, KubernetesJobRunner
from manifest_validator.service import ValidationService
from manifest_validator.trees import InMemoryTreeStore

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path("/config/manifest-validator.toml")


def build_checkers(
    settings: Settings, job_runner: JobRunner | None
) -> dict[str, Checker]:
    checkers: dict[str, Checker] = {}
    for check in settings.checks:
        checkers[check.name] = _build_checker(check, settings, job_runner)
    return checkers


def _build_checker(
    check: CheckConfig, settings: Settings, job_runner: JobRunner | None
) -> Checker:
    if check.kind == "structural":
        return StructuralChecker()
    if check.kind == "image-policy":
        return ImagePolicyChecker(
            allowed_registries=check.allowed_registries,
            require_pinned=check.require_pinned,
        )
    if job_runner is None:
        raise ValueError(
            f"check {check.name!r} needs a Job runner; "
            "in-cluster config was unavailable"
        )
    assert check.image is not None
    return JobChecker(
        check_name=check.name,
        image=check.image,
        args=check.args,
        runner=job_runner,
        tree_url_template=settings.jobs.tree_base_url.rstrip("/")
        + "/v1/trees/{digest}",
        ruleset_digest=check.ruleset_digest,
        tool_version=check.tool_version,
        fetcher_image=settings.jobs.fetcher_image,
        token_audience=settings.jobs.token_audience,
        timeout_seconds=settings.jobs.timeout_seconds,
        service_account=check.service_account,
        allow_egress=check.allow_egress,
        env=dict(check.env),
        findings_format=check.findings_format,
    )


def _job_runner(settings: Settings) -> JobRunner | None:
    if not any(check.kind == "job" for check in settings.checks):
        return None
    from kubernetes import client
    from kubernetes import config as kube_config
    from kubernetes.config.config_exception import ConfigException

    # Deliberately no fall back to a local kubeconfig: that would create Jobs
    # in whichever cluster happens to be the current context.
    try:
        kube_config.load_incluster_config()
    except ConfigException as exc:
        job_checks = [c.name for c in settings.checks if c.kind == "job"]
        raise SystemExit(
            f"checks {job_checks} need to run Jobs, which needs in-cluster "
            f"configuration ({exc}). For a local run use a config with only "
            "in-process checks, such as examples/local.toml."
        ) from None
    return KubernetesJobRunner(
        namespace=settings.jobs.namespace,
        batch_api=client.BatchV1Api(),
        core_api=client.CoreV1Api(),
    )


@click.command()
@click.option(
    "--config-path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=DEFAULT_CONFIG_PATH,
    show_default=True,
)
@click.option(
    "--disable-auth",
    is_flag=True,
    help="Skip bearer-token validation. Local runs only.",
)
def main(config_path: Path, disable_auth: bool) -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    settings = Settings.from_path(config_path)

    token_validator = None
    if disable_auth or settings.disable_auth:
        logger.warning("authentication is disabled; every caller is trusted")
    else:
        token_validator = TokenValidator(list(settings.roles))

    tree_store = InMemoryTreeStore()
    service = ValidationService(
        build_checkers(settings, _job_runner(settings)),
        tree_store,
        max_concurrent=settings.jobs.max_concurrent,
        default_checks=settings.default_check_names,
    )
    app = create_app(service, tree_store, token_validator)

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
