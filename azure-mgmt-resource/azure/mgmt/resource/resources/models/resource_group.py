# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class ResourceGroup(Model):
    """
    Resource group information.

    :param id: Gets the ID of the resource group.
    :type id: str
    :param name: Gets or sets the Name of the resource group.
    :type name: str
    :param properties:
    :type properties: :class:`ResourceGroupProperties
     <resourcemanagementclient.models.ResourceGroupProperties>`
    :param location: Gets or sets the location of the resource group. It
     cannot be changed after the resource group has been created. Has to be
     one of the supported Azure Locations, such as West US, East US, West
     Europe, East Asia, etc.
    :type location: str
    :param tags: Gets or sets the tags attached to the resource group.
    :type tags: dict
    """ 

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'ResourceGroupProperties'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, location, id=None, name=None, properties=None, tags=None):
        self.id = id
        self.name = name
        self.properties = properties
        self.location = location
        self.tags = tags
