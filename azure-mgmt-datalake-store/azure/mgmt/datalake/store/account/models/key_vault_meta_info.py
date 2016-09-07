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


class KeyVaultMetaInfo(Model):
    """KeyVaultMetaInfo.

    :param key_vault_resource_id: The resource identifier for the user
     managed Key Vault being used to encrypt.
    :type key_vault_resource_id: str
    :param encryption_key_name: The name of the user managed encryption key.
    :type encryption_key_name: str
    :param encryption_key_version: The version of the user managed encryption
     key.
    :type encryption_key_version: str
    """ 

    _attribute_map = {
        'key_vault_resource_id': {'key': 'keyVaultResourceId', 'type': 'str'},
        'encryption_key_name': {'key': 'encryptionKeyName', 'type': 'str'},
        'encryption_key_version': {'key': 'encryptionKeyVersion', 'type': 'str'},
    }

    def __init__(self, key_vault_resource_id=None, encryption_key_name=None, encryption_key_version=None):
        self.key_vault_resource_id = key_vault_resource_id
        self.encryption_key_name = encryption_key_name
        self.encryption_key_version = encryption_key_version
