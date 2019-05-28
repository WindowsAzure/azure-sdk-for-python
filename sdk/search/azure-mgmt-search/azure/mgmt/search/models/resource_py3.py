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
    """Base type for all Azure resources.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The ID of the resource. This can be used with the Azure Resource
     Manager to link resources together.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param location: The geographic location of the resource. This must be one
     of the supported and registered Azure Geo Regions (for example, West US,
     East US, Southeast Asia, and so forth). This property is required when
     creating a new resource.
    :type location: str
    :param tags: Tags to help categorize the resource in the Azure portal.
    :type tags: dict[str, str]
    :param identity: The identity of the resource.
    :type identity: ~azure.mgmt.search.models.Identity
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'identity': {'key': 'identity', 'type': 'Identity'},
    }

    def __init__(self, *, location: str=None, tags=None, identity=None, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = location
        self.tags = tags
        self.identity = identity
