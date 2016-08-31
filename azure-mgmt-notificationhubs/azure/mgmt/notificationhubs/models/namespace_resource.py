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


class NamespaceResource(Model):
    """Description of a Namespace resource.

    :param id: Gets or sets the id of the created Namespace.
    :type id: str
    :param location: Gets or sets datacenter location of the Namespace.
    :type location: str
    :param name: Gets or sets name of the Namespace.
    :type name: str
    :param type: Gets or sets resource type of the Namespace.
    :type type: str
    :param tags: Gets or sets tags of the Namespace.
    :type tags: dict
    :param properties: Gets or sets properties of the Namespace.
    :type properties: :class:`NamespaceProperties
     <azure.mgmt.notificationhubs.models.NamespaceProperties>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'NamespaceProperties'},
    }

    def __init__(self, id=None, location=None, name=None, type=None, tags=None, properties=None):
        self.id = id
        self.location = location
        self.name = name
        self.type = type
        self.tags = tags
        self.properties = properties
