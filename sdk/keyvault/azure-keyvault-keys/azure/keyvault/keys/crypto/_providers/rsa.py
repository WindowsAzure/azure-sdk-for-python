# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
from typing import TYPE_CHECKING

from .local_provider import LocalCryptographyProvider
from .._internal import RsaKey
from ... import JsonWebKey, KeyOperation, KeyType

if TYPE_CHECKING:
    # pylint:disable=unused-import
    from .local_provider import Algorithm
    from .._internal import Key

_PRIVATE_KEY_OPERATIONS = frozenset((KeyOperation.decrypt, KeyOperation.sign, KeyOperation.unwrap_key))


class RsaCryptographyProvider(LocalCryptographyProvider):
    def _get_internal_key(self, key):
        # type: (JsonWebKey) -> Key
        if key.kty not in (KeyType.rsa, KeyType.rsa_hsm):
            raise ValueError('"key" must be an RSA or RSA-HSM key')
        return RsaKey.from_jwk(key)

    def supports(self, operation, algorithm):
        # type: (KeyOperation, Algorithm) -> bool
        if operation in _PRIVATE_KEY_OPERATIONS and not self._internal_key.is_private_key():
            return False
        if operation in (KeyOperation.decrypt, KeyOperation.encrypt):
            return algorithm in self._internal_key.supported_encryption_algorithms
        if operation in (KeyOperation.unwrap_key, KeyOperation.wrap_key):
            return algorithm in self._internal_key.supported_key_wrap_algorithms
        if operation in (KeyOperation.sign, KeyOperation.verify):
            return algorithm in self._internal_key.supported_signature_algorithms
        return False
