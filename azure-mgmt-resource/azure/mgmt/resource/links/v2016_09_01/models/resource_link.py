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


class ResourceLink(Model):
    """The resource link.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The fully qualified ID of the resource link.
    :vartype id: str
    :ivar name: The name of the resource link.
    :vartype name: str
    :ivar type: The resource link object.
    :vartype type: object
    :param properties: Properties for resource link.
    :type properties:
     ~azure.mgmt.resource.links.v2016_09_01.models.ResourceLinkProperties
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'object'},
        'properties': {'key': 'properties', 'type': 'ResourceLinkProperties'},
    }

    def __init__(self, **kwargs):
        super(ResourceLink, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.properties = kwargs.get('properties', None)
