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
    """The core properties of ARM resources.

    :param id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/trafficManagerProfiles/{resourceName}
    :type id: str
    :param name: The name of the resource
    :type name: str
    :param type: The type of the resource. Ex-
     Microsoft.Network/trafficmanagerProfiles.
    :type type: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, id=None, name=None, type=None):
        super(Resource, self).__init__()
        self.id = id
        self.name = name
        self.type = type
