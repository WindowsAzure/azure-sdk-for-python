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
    """Describes a reference to Key Vault Key.

    :param key_url: The URL referencing a key encryption key in Key Vault.
    :type key_url: str
    :param source_vault: The relative URL of the Key Vault containing the key.
    :type source_vault:
     ~azure.mgmt.compute.v2017_12_01_preview.models.SubResource
    """

    _validation = {
        'key_url': {'required': True},
        'source_vault': {'required': True},
    }

    _attribute_map = {
        'key_url': {'key': 'keyUrl', 'type': 'str'},
        'source_vault': {'key': 'sourceVault', 'type': 'SubResource'},
    }

    def __init__(self, key_url, source_vault):
        self.key_url = key_url
        self.source_vault = source_vault
