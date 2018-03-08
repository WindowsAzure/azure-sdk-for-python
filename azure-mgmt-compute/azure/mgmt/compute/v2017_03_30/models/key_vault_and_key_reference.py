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


class KeyVaultAndKeyReference(Model):
    """Key Vault Key Url and vault id of KeK, KeK is optional and when provided is
    used to unwrap the encryptionKey.

    All required parameters must be populated in order to send to Azure.

    :param source_vault: Required. Resource id of the KeyVault containing the
     key or secret
    :type source_vault: ~azure.mgmt.compute.v2017_03_30.models.SourceVault
    :param key_url: Required. Url pointing to a key or secret in KeyVault
    :type key_url: str
    """

    _validation = {
        'source_vault': {'required': True},
        'key_url': {'required': True},
    }

    _attribute_map = {
        'source_vault': {'key': 'sourceVault', 'type': 'SourceVault'},
        'key_url': {'key': 'keyUrl', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(KeyVaultAndKeyReference, self).__init__(**kwargs)
        self.source_vault = kwargs.get('source_vault', None)
        self.key_url = kwargs.get('key_url', None)
