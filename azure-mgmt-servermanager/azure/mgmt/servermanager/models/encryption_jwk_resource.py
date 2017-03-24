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


class EncryptionJwkResource(Model):
    """The public key of the gateway.

    :param kty:
    :type kty: str
    :param alg:
    :type alg: str
    :param e:
    :type e: str
    :param n:
    :type n: str
    """

    _attribute_map = {
        'kty': {'key': 'kty', 'type': 'str'},
        'alg': {'key': 'alg', 'type': 'str'},
        'e': {'key': 'e', 'type': 'str'},
        'n': {'key': 'n', 'type': 'str'},
    }

    def __init__(self, kty=None, alg=None, e=None, n=None):
        self.kty = kty
        self.alg = alg
        self.e = e
        self.n = n
