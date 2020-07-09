# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import abc
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils

from ..algorithm import SignatureAlgorithm
from ..transform import SignatureTransform

if sys.version_info < (3, 3):
    abstractproperty = abc.abstractproperty
else:  # abc.abstractproperty is deprecated as of 3.3
    import functools

    abstractproperty = functools.partial(property, abc.abstractmethod)

class _EcdsaSignatureTransform(SignatureTransform):
    def __init__(self, key, hash_algorithm):
        super(_EcdsaSignatureTransform, self).__init__()

        self._key = key
        self._hash_algorithm = hash_algorithm

    def sign(self, digest):
        return self._key.sign(digest, ec.ECDSA(utils.Prehashed(self._hash_algorithm)))

    def verify(self, digest, signature):
        return self._key.verify(signature, digest, ec.ECDSA(utils.Prehashed(self._hash_algorithm)))


class _Ecdsa(SignatureAlgorithm):
    def create_signature_transform(self, key):
        return _EcdsaSignatureTransform(key, self.default_hash_algorithm)

    @abstractproperty
    def coordinate_length(self):
        pass


class Ecdsa256(_Ecdsa):
    _name = "ES256K"
    _default_hash_algorithm = hashes.SHA256()
    coordinate_length = 32


class Es256(_Ecdsa):
    _name = "ES256"
    _default_hash_algorithm = hashes.SHA256()
    coordinate_length = 32


class Es384(_Ecdsa):
    _name = "ES384"
    _default_hash_algorithm = hashes.SHA384()
    coordinate_length = 48


class Es512(_Ecdsa):
    _name = "ES512"
    _default_hash_algorithm = hashes.SHA512()
    coordinate_length = 66


Ecdsa256.register()
Es256.register()
Es384.register()
Es512.register()
