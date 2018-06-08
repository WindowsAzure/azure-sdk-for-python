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


class KeyProperties(Model):
    """Properties of the key pair backing a certificate.

    :param exportable: Indicates if the private key can be exported.
    :type exportable: bool
    :param key_type: The key type.
    :type key_type: str
    :param key_size: The key size in bits. For example: 2048, 3072, or 4096
     for RSA.
    :type key_size: int
    :param reuse_key: Indicates if the same key pair will be used on
     certificate renewal.
    :type reuse_key: bool
    :param curve: Elliptic curve name. For valid values, see
     JsonWebKeyCurveName. Possible values include: 'P-256', 'P-384', 'P-521',
     'SECP256K1'
    :type curve: str or ~azure.keyvault.models.JsonWebKeyCurveName
    """

    _attribute_map = {
        'exportable': {'key': 'exportable', 'type': 'bool'},
        'key_type': {'key': 'kty', 'type': 'str'},
        'key_size': {'key': 'key_size', 'type': 'int'},
        'reuse_key': {'key': 'reuse_key', 'type': 'bool'},
        'curve': {'key': 'crv', 'type': 'str'},
    }

    def __init__(self, *, exportable: bool=None, key_type: str=None, key_size: int=None, reuse_key: bool=None, curve=None, **kwargs) -> None:
        super(KeyProperties, self).__init__(**kwargs)
        self.exportable = exportable
        self.key_type = key_type
        self.key_size = key_size
        self.reuse_key = reuse_key
        self.curve = curve
