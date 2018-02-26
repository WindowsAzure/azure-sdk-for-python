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

    :param sku: The SKU (pricing tier) of the server.
    :type sku: ~azure.mgmt.rdbms.mysql.models.Sku
    :param properties: Properties of the server.
    :type properties: ~azure.mgmt.rdbms.mysql.models.ServerPropertiesForCreate
    :param location: The location the resource resides in.
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

    def __init__(self, properties, location, sku=None, tags=None):
        super(ServerForCreate, self).__init__()
        self.sku = sku
        self.properties = properties
        self.location = location
        self.tags = tags
