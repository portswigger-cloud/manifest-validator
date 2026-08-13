# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

JWKS_CACHE_TTL_SECONDS = 3600


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class RoleConfig:
    """A caller identity, matched on issuer, audience and exact claims.

    Deliberately the same TOML shape as relcoord's `[[role]]`, because the tree
    endpoint serves the trust configuration and must be no easier to reach than
    the endpoint that generated it.
    """

    name: str
    issuer: str
    audience: str
    claims: dict[str, str] = field(default_factory=dict)
    jwks_uri: str | None = None

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> RoleConfig:
        for key in ("name", "issuer", "audience"):
            value = data.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"role.{key} must be a non-empty string")
        claims = data.get("claims", {})
        if not isinstance(claims, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in claims.items()
        ):
            raise ValueError(
                f"role.{data['name']}.claims must be a table of string to string"
            )
        jwks_uri = data.get("jwks-uri")
        if jwks_uri is not None and not isinstance(jwks_uri, str):
            raise ValueError(f"role.{data['name']}.jwks-uri must be a string")
        return cls(
            name=data["name"],
            issuer=data["issuer"],
            audience=data["audience"],
            claims=dict(claims),
            jwks_uri=jwks_uri,
        )


@dataclass(frozen=True)
class ValidatedClaims:
    role: str
    payload: dict[str, Any]

    @property
    def subject(self) -> str:
        return str(self.payload.get("sub", "unknown"))


class _JwkClientCache:
    def __init__(self, ttl_seconds: int = JWKS_CACHE_TTL_SECONDS) -> None:
        self._clients: dict[str, tuple[float, PyJWKClient]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def get(self, uri: str) -> PyJWKClient:
        now = time.monotonic()
        with self._lock:
            entry = self._clients.get(uri)
            if entry is not None and entry[0] > now:
                return entry[1]
            client = PyJWKClient(uri)
            self._clients[uri] = (now + self._ttl, client)
            return client


class TokenValidator:
    def __init__(self, roles: list[RoleConfig]) -> None:
        if not roles:
            raise ValueError(
                "at least one [[role]] is required unless auth is disabled"
            )
        self._roles = roles
        self._jwk_clients = _JwkClientCache()
        self._jwks_uris: dict[str, str] = {}

    def validate(self, bearer_token: str) -> ValidatedClaims:
        failures: list[str] = []
        for role in self._roles:
            try:
                payload = self._validate_for_role(bearer_token, role)
            except Exception as exc:
                failures.append(f"{role.name}: {exc}")
                continue
            mismatched = {
                key: payload.get(key)
                for key, expected in role.claims.items()
                if payload.get(key) != expected
            }
            if mismatched:
                failures.append(f"{role.name}: claim mismatch on {sorted(mismatched)}")
                continue
            return ValidatedClaims(role=role.name, payload=payload)
        raise AuthError("no configured role accepted the token: " + "; ".join(failures))

    def _validate_for_role(self, token: str, role: RoleConfig) -> dict[str, Any]:
        signing_key = self._jwk_clients.get(
            self._jwks_uri_for(role)
        ).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=role.audience,
            issuer=role.issuer,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )

    def _jwks_uri_for(self, role: RoleConfig) -> str:
        if role.jwks_uri is not None:
            return role.jwks_uri
        cached = self._jwks_uris.get(role.issuer)
        if cached is not None:
            return cached
        discovery = role.issuer.rstrip("/") + "/.well-known/openid-configuration"
        response = httpx.get(discovery, timeout=10.0)
        response.raise_for_status()
        uri = response.json().get("jwks_uri")
        if not isinstance(uri, str):
            raise AuthError(f"{discovery} did not advertise a jwks_uri")
        self._jwks_uris[role.issuer] = uri
        return uri


def extract_bearer_token(authorization_header: str | None) -> str:
    if not authorization_header:
        raise AuthError("missing Authorization header")
    scheme, _, token = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthError("Authorization header is not a bearer token")
    return token.strip()
