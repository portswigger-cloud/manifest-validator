# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 PortSwigger Ltd
from __future__ import annotations


class ManifestValidatorError(Exception):
    pass


class DigestMismatch(ManifestValidatorError):
    pass


class MalformedTree(ManifestValidatorError):
    pass


class UnknownTree(ManifestValidatorError):
    pass


class UnknownCheck(ManifestValidatorError):
    pass


class CheckTimeout(ManifestValidatorError):
    pass


class DisallowedImage(ManifestValidatorError):
    pass
