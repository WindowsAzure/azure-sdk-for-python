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


class Resource(Model):
    """Model of the Resource.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. The location of the resource. This will be one
     of the supported and registered Azure Regions (e.g. West US, East US,
     Southeast Asia, etc.). The region of a resource cannot be changed once it
     is created, but if an identical region is specified on update the request
     will succeed.
    :type location: str
    :param tags: The list of key value pairs that describe the resource. These
     tags can be used in viewing and grouping this resource (across resource
     groups).
    :type tags: dict[str, str]
    :param sku: Required. The sku type.
    :type sku: ~azure.mgmt.databox.models.Sku
    """

    _validation = {
        'location': {'required': True},
        'sku': {'required': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
    }

    def __init__(self, *, location: str, sku, tags=None, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.location = location
        self.tags = tags
        self.sku = sku
