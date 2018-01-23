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


class ResourceGroupPatchable(Model):
    """Resource group information.

    :param name: The name of the resource group.
    :type name: str
    :param properties:
    :type properties:
     ~azure.mgmt.resource.resources.v2017_05_10.models.ResourceGroupProperties
    :param managed_by: The ID of the resource that manages this resource
     group.
    :type managed_by: str
    :param tags: The tags attached to the resource group.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'ResourceGroupProperties'},
        'managed_by': {'key': 'managedBy', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, name=None, properties=None, managed_by=None, tags=None):
        super(ResourceGroupPatchable, self).__init__()
        self.name = name
        self.properties = properties
        self.managed_by = managed_by
        self.tags = tags
