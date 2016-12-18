# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class JsonWebKey(Model):
    """As of http://tools.ietf.org/html/draft-ietf-jose-json-web-key-18.

    :param kid: Key Identifier
    :type kid: str
    :param kty: Supported JsonWebKey key types (kty) for Elliptic Curve, RSA,
     HSM, Octet, usually RSA. Possible values include: 'EC', 'RSA', 'RSA-HSM',
     'oct'
    :type kty: str or :class:`JsonWebKeyType
     <azure.keyvault.models.JsonWebKeyType>`
    :param key_ops:
    :type key_ops: list of str
    :param n: RSA modulus
    :type n: bytes
    :param e: RSA public exponent
    :type e: bytes
    :param d: RSA private exponent
    :type d: bytes
    :param dp: RSA Private Key Parameter
    :type dp: bytes
    :param dq: RSA Private Key Parameter
    :type dq: bytes
    :param qi: RSA Private Key Parameter
    :type qi: bytes
    :param p: RSA secret prime
    :type p: bytes
    :param q: RSA secret prime, with p < q
    :type q: bytes
    :param k: Symmetric key
    :type k: bytes
    :param t: HSM Token, used with Bring Your Own Key
    :type t: bytes
    """

    _attribute_map = {
        'kid': {'key': 'kid', 'type': 'str'},
        'kty': {'key': 'kty', 'type': 'str'},
        'key_ops': {'key': 'key_ops', 'type': '[str]'},
        'n': {'key': 'n', 'type': 'base64'},
        'e': {'key': 'e', 'type': 'base64'},
        'd': {'key': 'd', 'type': 'base64'},
        'dp': {'key': 'dp', 'type': 'base64'},
        'dq': {'key': 'dq', 'type': 'base64'},
        'qi': {'key': 'qi', 'type': 'base64'},
        'p': {'key': 'p', 'type': 'base64'},
        'q': {'key': 'q', 'type': 'base64'},
        'k': {'key': 'k', 'type': 'base64'},
        't': {'key': 'key_hsm', 'type': 'base64'},
    }

    def __init__(self, kid=None, kty=None, key_ops=None, n=None, e=None, d=None, dp=None, dq=None, qi=None, p=None, q=None, k=None, t=None):
        self.kid = kid
        self.kty = kty
        self.key_ops = key_ops
        self.n = n
        self.e = e
        self.d = d
        self.dp = dp
        self.dq = dq
        self.qi = qi
        self.p = p
        self.q = q
        self.k = k
        self.t = t
