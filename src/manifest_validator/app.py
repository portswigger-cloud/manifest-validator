# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import json
import logging
import queue
import threading
from collections.abc import Iterator, Sequence
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from manifest_validator.auth import AuthError, TokenValidator, extract_bearer_token
from manifest_validator.errors import (
    DigestMismatch,
    MalformedTree,
    UnknownCheck,
    UnknownTree,
)
from manifest_validator.models import ValidationResult
from manifest_validator.service import ValidationService
from manifest_validator.trees import TreeStore, from_tar_gz, to_tar

logger = logging.getLogger(__name__)

SSE_MEDIA_TYPE = "text/event-stream"
_SENTINEL = object()


def create_app(
    service: ValidationService,
    tree_store: TreeStore,
    token_validator: TokenValidator | None,
) -> Starlette:
    """Wire the HTTP surface.

    `token_validator` of None disables authentication and is for local runs
    only; `main` refuses to do it unless asked explicitly.
    """

    def authenticate(request: Request) -> str:
        if token_validator is None:
            return "auth-disabled"
        claims = token_validator.validate(
            extract_bearer_token(request.headers.get("authorization"))
        )
        return claims.role

    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def validate(request: Request) -> Response:
        try:
            role = authenticate(request)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)

        try:
            digest, checks = _parse_validate_params(request)
            files = from_tar_gz(await request.body())
        except (ValueError, MalformedTree) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)

        logger.info(
            "validate digest=%s files=%d role=%s checks=%s",
            digest,
            len(files),
            role,
            checks or "default",
        )

        wants_stream = SSE_MEDIA_TYPE in (request.headers.get("accept") or "")
        if wants_stream:
            return StreamingResponse(
                _stream(service, digest, files, checks),
                media_type=SSE_MEDIA_TYPE,
                headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
            )

        def run() -> ValidationResult:
            return service.validate(digest, files, _discard_progress, checks)

        try:
            result = await run_in_threadpool(run)
        except DigestMismatch as exc:
            return JSONResponse({"error": f"digest mismatch: {exc}"}, status_code=400)
        except UnknownCheck as exc:
            return JSONResponse({"error": f"unknown check: {exc}"}, status_code=400)
        return JSONResponse(result.as_dict())

    async def get_tree(request: Request) -> Response:
        try:
            authenticate(request)
        except AuthError as exc:
            return JSONResponse({"error": str(exc)}, status_code=401)
        digest = request.path_params["digest"]
        try:
            tree = tree_store.get(digest)
        except UnknownTree:
            return JSONResponse({"error": "no such tree"}, status_code=404)
        return Response(
            content=to_tar(tree),
            media_type="application/x-tar",
            headers={"Cache-Control": "no-store"},
        )

    return Starlette(
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/v1/validate", validate, methods=["POST"]),
            Route("/v1/trees/{digest}", get_tree, methods=["GET"]),
        ]
    )


def _parse_validate_params(request: Request) -> tuple[str, tuple[str, ...] | None]:
    """The body is the tree itself, so everything else travels in the query."""
    digest = request.query_params.get("digest")
    if not digest or not digest.startswith("sha256:"):
        raise ValueError("digest query parameter must be of the form 'sha256:...'")
    checks = tuple(request.query_params.getlist("check"))
    return digest, checks or None


def _discard_progress(phase: str, message: str) -> None:
    logger.info("%s: %s", phase, message)


def _stream(
    service: ValidationService,
    digest: str,
    files: dict[str, bytes],
    checks: Sequence[str] | None,
) -> Iterator[bytes]:
    """Run the validation on a worker thread, forwarding progress as SSE.

    relcoord forwards these events into its own stream, which is what puts scan
    progress into the pull request without any CI change.
    """
    events: queue.Queue[Any] = queue.Queue()

    def progress(phase: str, message: str) -> None:
        events.put({"event": phase, "data": {"message": message}})

    def run() -> None:
        try:
            result = service.validate(digest, files, progress, checks)
            events.put({"event": "result", "data": result.as_dict()})
        except DigestMismatch as exc:
            events.put(
                {"event": "error", "data": {"message": f"digest mismatch: {exc}"}}
            )
        except UnknownCheck as exc:
            events.put({"event": "error", "data": {"message": f"unknown check: {exc}"}})
        except Exception as exc:
            logger.exception("validation failed")
            events.put({"event": "error", "data": {"message": str(exc)}})
        finally:
            events.put(_SENTINEL)

    worker = threading.Thread(target=run, name="validate", daemon=True)
    worker.start()
    while True:
        item = events.get()
        if item is _SENTINEL:
            return
        yield _sse(item["event"], item["data"])


def _sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()
