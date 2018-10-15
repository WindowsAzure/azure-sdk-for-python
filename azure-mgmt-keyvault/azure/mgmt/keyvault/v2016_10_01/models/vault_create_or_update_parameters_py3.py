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


class VaultCreateOrUpdateParameters(Model):
    """Parameters for creating or updating a vault.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. The supported Azure location where the key
     vault should be created.
    :type location: str
    :param tags: The tags that will be assigned to the key vault.
    :type tags: dict[str, str]
    :param properties: Required. Properties of the vault
    :type properties: ~azure.mgmt.keyvault.v2016_10_01.models.VaultProperties
    """

    _validation = {
        'location': {'required': True},
        'properties': {'required': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'VaultProperties'},
    }

    def __init__(self, *, location: str, properties, tags=None, **kwargs) -> None:
        super(VaultCreateOrUpdateParameters, self).__init__(**kwargs)
        self.location = location
        self.tags = tags
        self.properties = properties
