# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import base64
import binascii
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
    UnknownCheck,
    UnknownTree,
)
from manifest_validator.models import ValidationResult
from manifest_validator.service import ValidationService
from manifest_validator.trees import TreeStore, to_tar

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
            payload = await request.json()
            digest, files, checks = _parse_validate_request(payload)
        except (ValueError, json.JSONDecodeError) as exc:
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


def _parse_validate_request(
    payload: Any,
) -> tuple[str, dict[str, bytes], tuple[str, ...] | None]:
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    digest = payload.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("digest must be a string of the form 'sha256:...'")
    raw_files = payload.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise ValueError("files must be a non-empty object of path to base64 content")
    files: dict[str, bytes] = {}
    for path, encoded in raw_files.items():
        if not isinstance(path, str) or not isinstance(encoded, str):
            raise ValueError("files keys and values must be strings")
        if path.startswith("/") or ".." in path.split("/"):
            raise ValueError(f"file path {path!r} must be relative and without '..'")
        try:
            files[path] = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"file {path!r} is not valid base64: {exc}") from None
    checks = payload.get("checks")
    if checks is None:
        return digest, files, None
    if not isinstance(checks, list) or not all(isinstance(c, str) for c in checks):
        raise ValueError("checks must be a list of strings")
    return digest, files, tuple(checks)


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
