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


class SyncGroupCreateParameters(Model):
    """The parameters used when creating a sync group.

    :param location: Required. Gets or sets the location of the resource. This
     will be one of the supported and registered Azure Geo Regions (e.g. West
     US, East US, Southeast Asia, etc.). The geo region of a resource cannot be
     changed once it is created, but if an identical geo region is specified on
     update, the request will succeed.
    :type location: str
    :param tags: Gets or sets a list of key value pairs that describe the
     resource. These tags can be used for viewing and grouping this resource
     (across resource groups). A maximum of 15 tags can be provided for a
     resource. Each tag must have a key with a length no greater than 128
     characters and a value with a length no greater than 256 characters.
    :type tags: dict[str, str]
    :param properties: The parameters used to create the sync group
    :type properties: object
    """

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'properties': {'key': 'properties', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(SyncGroupCreateParameters, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)
        self.properties = kwargs.get('properties', None)
