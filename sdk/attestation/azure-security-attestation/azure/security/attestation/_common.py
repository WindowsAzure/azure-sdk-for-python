# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any


import base64


class Base64Url:
    """Equivalent to base64.urlsafe_b64encode, but strips padding from the encoded and decoded strings."""

    @staticmethod
    def encode(unencoded):
        # type(bytes)->str
        base64val = base64.urlsafe_b64encode(unencoded)
        strip_trailing = base64val.split(b"=")[
            0
        ]  # pick the string before the trailing =
        return strip_trailing.decode("utf-8")

    @staticmethod
    def decode(encoded):
        # type(str)->bytes
        padding_added = encoded + "=" * ((len(encoded) * -1) % 4)
        return base64.urlsafe_b64decode(padding_added.encode("utf-8"))


def pem_from_base64(base64_value, header_type):
    # type: (str, str) -> str
    pem = "-----BEGIN " + header_type + "-----\n"
    while base64_value != "":
        pem += base64_value[:64] + "\n"
        base64_value = base64_value[64:]
    pem += "-----END " + header_type + "-----\n"
    return pem


def validate_signing_keys(signing_key_pem, certificate_pem):
    """Validates the attestation signing key and certificates specified.

    :param str signing_key_pem: PEM encoded EC or RSA signing key.
    :param str certificate_pem: PEM encoded X.509 certificate.
    :return: Returns the decoded signing key and certificate
    :rtype: RSAPrivateKey or ElilipticCurvePrivateKey, Certificate

    The validate_signing_keys method decodes the signing key and certificate
    and verifies that the public key associated with the certificate and the
    signing key are the same key.

    :staticmethod:
    """
    # type (str, str) -> cryptography.hazmat.primatives.asymmetric.ec | cryptography.hazmat.primatives.asymmetric.rsa, Certificate

    # Start by making sure that both signing key and certificate are present.
    if signing_key_pem and not certificate_pem:
        raise ValueError("signing_key cannot be specified without signing_certificate.")
    if certificate_pem and not signing_key_pem:
        raise ValueError("signing_certificate cannot be specified without signing_key.")

    # Verify that the key and certificate are validly PEM encoded.
    signing_key = serialization.load_pem_private_key(
        signing_key_pem.encode("utf-8"), password=None, backend=default_backend()
    )
    certificate = load_pem_x509_certificate(
        certificate_pem.encode("utf-8"), backend=default_backend()
    )

    # We only support ECDS and RSA keys in the MAA service.
    if not isinstance(signing_key, RSAPrivateKey) and not isinstance(
        signing_key, EllipticCurvePrivateKey
    ):
        raise ValueError("Signing keys must be either ECDS or RSA keys.")

    # Ensure that the public key in the certificate matches the public key of the key.
    cert_public_key = certificate.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    key_public_key = signing_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    if cert_public_key != key_public_key:
        raise ValueError("Signing key must match certificate public key")
    return signing_key, certificate


def merge_validation_args(existing_options, kwargs):
    # type(Dict[str, Any], Dict[str, Any]) -> Dict[str, Any]
    options = existing_options.copy()
    options.update(**kwargs)

    # There are elements in the core pipelines that expect that there are no
    # keyword arguments passed in that aren't those they expect, so remove
    # the validation keyword arguments now to make the downstream code happy.
    kwargs.pop("validate_token", None)
    kwargs.pop("validation_callback", None)
    kwargs.pop("validate_signature", None)
    kwargs.pop("validate_expiration", None)
    kwargs.pop("validate_not_before", None)
    kwargs.pop("validate_issuer", None)
    kwargs.pop("issuer", None)
    kwargs.pop("validation_slack", None)

    return options
