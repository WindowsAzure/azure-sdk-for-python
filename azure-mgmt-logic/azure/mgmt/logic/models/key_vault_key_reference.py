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


class KeyVaultKeyReference(Model):
    """The reference to the key vault key.

    All required parameters must be populated in order to send to Azure.

    :param key_vault: Required. The key vault reference.
    :type key_vault: ~azure.mgmt.logic.models.KeyVaultKeyReferenceKeyVault
    :param key_name: Required. The private key name in key vault.
    :type key_name: str
    :param key_version: The private key version in key vault.
    :type key_version: str
    """

    _validation = {
        'key_vault': {'required': True},
        'key_name': {'required': True},
    }

    _attribute_map = {
        'key_vault': {'key': 'keyVault', 'type': 'KeyVaultKeyReferenceKeyVault'},
        'key_name': {'key': 'keyName', 'type': 'str'},
        'key_version': {'key': 'keyVersion', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(KeyVaultKeyReference, self).__init__(**kwargs)
        self.key_vault = kwargs.get('key_vault', None)
        self.key_name = kwargs.get('key_name', None)
        self.key_version = kwargs.get('key_version', None)
