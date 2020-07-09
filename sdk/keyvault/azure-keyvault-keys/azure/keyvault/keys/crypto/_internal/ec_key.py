# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    SECP256K1,
)

from ._internal import _bytes_to_int, asn1_der_to_ecdsa, ecdsa_to_asn1_der
from .key import Key
from .algorithms.ecdsa import Es256, Es512, Es384, Ecdsa256

_crypto_crv_to_kv_crv = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521", "secp256k1": "P-256K"}
_kv_crv_to_crypto_cls = {
    "P-256": SECP256R1,
    "P-256K": SECP256K1,
    "P-384": SECP384R1,
    "P-521": SECP521R1,
    "SECP256K1": SECP256K1,
}
_curve_to_default_algo = {
    "P-256": Es256.name(),
    "P-256K": Ecdsa256.name(),
    "P-384": Es384.name(),
    "P-521": Es512.name(),
    "SECP256K1": Ecdsa256.name(),
}


class EllipticCurveKey(Key):
    _supported_signature_algorithms = _curve_to_default_algo.values()

    def __init__(self, x, y, d=None, kid=None, curve=None):
        super(EllipticCurveKey, self).__init__()

        self._kid = kid or str(uuid.uuid4())
        self._default_algo = _curve_to_default_algo[curve]
        curve_cls = _kv_crv_to_crypto_cls[curve]

        public_numbers = EllipticCurvePublicNumbers(x, y, curve_cls())
        self._public_key = public_numbers.public_key(default_backend())
        self._private_key = None
        if d is not None:
            private_numbers = EllipticCurvePrivateNumbers(d, public_numbers)
            self._private_key = private_numbers.private_key(default_backend())

    @classmethod
    def from_jwk(cls, jwk):
        if jwk.kty != "EC" and jwk.kty != "EC-HSM":
            raise ValueError("The specified key must be of type 'EC' or 'EC-HSM'")

        if not jwk.x or not jwk.y:
            raise ValueError("jwk must have values for 'x' and 'y'")

        x = _bytes_to_int(jwk.x)
        y = _bytes_to_int(jwk.y)
        d = _bytes_to_int(jwk.d) if jwk.d is not None else None
        return cls(x, y, d, kid=jwk.kid, curve=jwk.crv)

    def is_private_key(self):
        return self._private_key is not None

    def decrypt(self, cipher_text, **kwargs):
        raise NotImplementedError("Local decryption isn't supported with elliptic curve keys")

    def encrypt(self, plain_text, **kwargs):
        raise NotImplementedError("Local encryption isn't supported with elliptic curve keys")

    def wrap_key(self, key, **kwargs):
        raise NotImplementedError("Local key wrapping isn't supported with elliptic curve keys")

    def unwrap_key(self, encrypted_key, **kwargs):
        raise NotImplementedError("Local key unwrapping isn't supported with elliptic curve keys")

    def sign(self, digest, **kwargs):
        algorithm = self._get_algorithm("sign", **kwargs)
        signer = algorithm.create_signature_transform(self._private_key)
        signature = signer.sign(digest)
        ecdsa_signature = asn1_der_to_ecdsa(signature, algorithm)
        return ecdsa_signature

    def verify(self, digest, signature, **kwargs):
        algorithm = self._get_algorithm("verify", **kwargs)
        signer = algorithm.create_signature_transform(self._public_key)
        asn1_signature = ecdsa_to_asn1_der(signature)
        try:
            signer.verify(digest, asn1_signature)
            return True
        except InvalidSignature:
            return False
