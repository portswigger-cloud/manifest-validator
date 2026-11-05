# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations


class ManifestValidatorError(Exception):
    pass


class DigestMismatch(ManifestValidatorError):
    pass


class MalformedTree(ManifestValidatorError):
    pass


class UnknownCheck(ManifestValidatorError):
    pass


class CheckTimeout(ManifestValidatorError):
    pass


class DisallowedImage(ManifestValidatorError):
    pass


class RegistryCredentialError(ManifestValidatorError):
    """A declared registry credential could not be produced."""


class RegistryUnreachable(ManifestValidatorError):
    """Whatever issues a registry credential could not be reached.

    Kept apart from RegistryCredentialError because only a refusal stops the
    service from starting: an outage says nothing about the credential.
    """
