# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

from typing import Any

from botocore.exceptions import EndpointConnectionError

from manifest_validator.dynamodb_store import DynamoDBScanStore

TABLE = "manifest-validator-scans"
NOW = 1_000_000


class FakeDynamoDBClient:
    """Enough of batch_get_item and batch_write_item to hold items by `pk`."""

    def __init__(self, *, unprocessed_rounds: int = 0) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.get_sizes: list[int] = []
        self.put_sizes: list[int] = []
        self._unprocessed_rounds = unprocessed_rounds

    def batch_get_item(self, RequestItems: dict[str, Any]) -> dict[str, Any]:  # noqa: N803
        request = RequestItems[TABLE]
        keys = [k["pk"]["S"] for k in request["Keys"]]
        self.get_sizes.append(len(keys))
        if self._unprocessed_rounds:
            self._unprocessed_rounds -= 1
            return {"Responses": {TABLE: []}, "UnprocessedKeys": RequestItems}
        found = [self.items[k] for k in keys if k in self.items]
        return {"Responses": {TABLE: found}, "UnprocessedKeys": {}}

    def batch_write_item(self, RequestItems: dict[str, Any]) -> dict[str, Any]:  # noqa: N803
        requests = RequestItems[TABLE]
        self.put_sizes.append(len(requests))
        if self._unprocessed_rounds:
            self._unprocessed_rounds -= 1
            return {"UnprocessedItems": RequestItems}
        for request in requests:
            item = request["PutRequest"]["Item"]
            self.items[item["pk"]["S"]] = item
        return {"UnprocessedItems": {}}


class Unreachable:
    def batch_get_item(self, **kwargs: Any) -> dict[str, Any]:
        raise EndpointConnectionError(endpoint_url="https://dynamodb")

    def batch_write_item(self, **kwargs: Any) -> dict[str, Any]:
        raise EndpointConnectionError(endpoint_url="https://dynamodb")


def _store(
    client: object, now: float = NOW, ttl_seconds: int = 60
) -> DynamoDBScanStore:
    return DynamoDBScanStore(
        client, TABLE, ttl_seconds, clock=lambda: now, sleep=lambda _: None
    )


def test_what_is_put_can_be_got() -> None:
    client = FakeDynamoDBClient()
    _store(client).put_many({"k1": "one", "k2": "two"})
    assert _store(client).get_many(["k1", "k2", "k3"]) == {"k1": "one", "k2": "two"}


def test_an_expired_item_is_ignored_before_dynamodb_deletes_it() -> None:
    client = FakeDynamoDBClient()
    _store(client, ttl_seconds=60).put_many({"k": "v"})
    assert _store(client, now=NOW + 59).get_many(["k"]) == {"k": "v"}
    assert _store(client, now=NOW + 60).get_many(["k"]) == {}


def test_requests_stay_within_dynamodb_batch_limits() -> None:
    client = FakeDynamoDBClient()
    keys = [f"k{i}" for i in range(230)]
    _store(client).put_many(dict.fromkeys(keys, "v"))
    _store(client).get_many(keys)
    assert client.put_sizes == [25] * 9 + [5]
    assert client.get_sizes == [100, 100, 30]


def test_unprocessed_keys_are_retried() -> None:
    client = FakeDynamoDBClient()
    _store(client).put_many({"k": "v"})
    client._unprocessed_rounds = 2
    assert _store(client).get_many(["k"]) == {"k": "v"}


def test_throttling_that_outlasts_the_retries_reads_as_a_miss() -> None:
    client = FakeDynamoDBClient()
    _store(client).put_many({"k": "v"})
    client._unprocessed_rounds = 5
    assert _store(client).get_many(["k"]) == {}


def test_unprocessed_writes_are_retried() -> None:
    client = FakeDynamoDBClient(unprocessed_rounds=1)
    _store(client).put_many({"k": "v"})
    assert "k" in client.items


def test_an_unreachable_table_behaves_as_empty_rather_than_failing() -> None:
    store = _store(Unreachable())
    store.put_many({"k": "v"})
    assert store.get_many(["k"]) == {}
