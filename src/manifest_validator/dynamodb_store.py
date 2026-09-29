# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Collection, Mapping
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from manifest_validator.config import ScanCacheSettings

logger = logging.getLogger(__name__)

# DynamoDB's own per-request limits.
_GET_BATCH = 100
_PUT_BATCH = 25
_ATTEMPTS = 3
_BACKOFF_SECONDS = 0.05

# botocore's defaults spent about 25s failing each call against a table that was
# down, and a tree takes over a dozen calls. A cache is only worth waiting for
# briefly.
_CLIENT_CONFIG = Config(
    connect_timeout=2,
    read_timeout=5,
    retries={"mode": "standard", "max_attempts": 2},
)


class _Unavailable(Exception):
    pass


class DynamoDBScanStore:
    """Remembered findings in a table keyed on `pk`, expired by DynamoDB TTL.

    TTL deletion runs up to days behind, so an expired item is also ignored on
    read. Throttling that outlasts a few retries leaves keys unread or unwritten,
    which costs a rescan and nothing else. A call that fails outright abandons
    the rest of that read or write rather than failing each batch in turn.
    """

    def __init__(
        self,
        client: Any,
        table_name: str,
        ttl_seconds: int,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client
        self._table_name = table_name
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._sleep = sleep

    @classmethod
    def connect(cls, settings: ScanCacheSettings) -> DynamoDBScanStore:
        client = boto3.client(
            "dynamodb",
            region_name=settings.region_name,
            endpoint_url=settings.endpoint_url,
            config=_CLIENT_CONFIG,
        )
        logger.info("remembering scans in DynamoDB table %s", settings.table_name)
        return cls(client, settings.table_name, settings.ttl_days * 86_400)

    def get_many(self, keys: Collection[str]) -> dict[str, str]:
        found: dict[str, str] = {}
        now = int(self._clock())
        ordered = sorted(keys)
        try:
            for start in range(0, len(ordered), _GET_BATCH):
                found |= self._get_batch(ordered[start : start + _GET_BATCH], now)
        except _Unavailable:
            pass
        return found

    def _get_batch(self, keys: list[str], now: int) -> dict[str, str]:
        request = {
            self._table_name: {
                "Keys": [{"pk": {"S": k}} for k in keys],
                "ProjectionExpression": "#pk, #scan, #expires",
                "ExpressionAttributeNames": {
                    "#pk": "pk",
                    "#scan": "scan",
                    "#expires": "expires",
                },
            }
        }
        return {
            item["pk"]["S"]: item["scan"]["S"]
            for item in self._batch_get(request)
            if int(item["expires"]["N"]) > now
        }

    def put_many(self, entries: Mapping[str, str]) -> None:
        expires = str(int(self._clock()) + self._ttl_seconds)
        requests = [
            {
                "PutRequest": {
                    "Item": {
                        "pk": {"S": key},
                        "scan": {"S": scan},
                        "expires": {"N": expires},
                    }
                }
            }
            for key, scan in entries.items()
        ]
        try:
            for start in range(0, len(requests), _PUT_BATCH):
                self._batch_write(
                    {self._table_name: requests[start : start + _PUT_BATCH]}
                )
        except _Unavailable:
            pass

    def _batch_get(self, request: dict[str, Any]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for attempt in range(_ATTEMPTS):
            if attempt:
                self._sleep(_BACKOFF_SECONDS * 2**attempt)
            try:
                response = self._client.batch_get_item(RequestItems=request)
            except (BotoCoreError, ClientError) as exc:
                logger.warning("could not read remembered scans: %s", exc)
                raise _Unavailable from exc
            items.extend(response.get("Responses", {}).get(self._table_name, []))
            request = response.get("UnprocessedKeys") or {}
            if not request:
                return items
        logger.warning("DynamoDB left some remembered scans unread")
        return items

    def _batch_write(self, request: dict[str, Any]) -> None:
        for attempt in range(_ATTEMPTS):
            if attempt:
                self._sleep(_BACKOFF_SECONDS * 2**attempt)
            try:
                response = self._client.batch_write_item(RequestItems=request)
            except (BotoCoreError, ClientError) as exc:
                logger.warning("could not remember scans: %s", exc)
                raise _Unavailable from exc
            request = response.get("UnprocessedItems") or {}
            if not request:
                return
        logger.warning("DynamoDB left some scans unremembered")
