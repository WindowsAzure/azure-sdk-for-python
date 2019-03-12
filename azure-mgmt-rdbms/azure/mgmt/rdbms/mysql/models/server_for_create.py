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


class ServerForCreate(Model):
    """Represents a server to be created.

    All required parameters must be populated in order to send to Azure.

    :param sku: The SKU (pricing tier) of the server.
    :type sku: ~azure.mgmt.rdbms.mysql.models.Sku
    :param properties: Required. Properties of the server.
    :type properties: ~azure.mgmt.rdbms.mysql.models.ServerPropertiesForCreate
    :param location: Required. The location the resource resides in.
    :type location: str
    :param tags: Application-specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    """

    _validation = {
        'properties': {'required': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'Sku'},
        'properties': {'key': 'properties', 'type': 'ServerPropertiesForCreate'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(ServerForCreate, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.properties = kwargs.get('properties', None)
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)
