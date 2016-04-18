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


class NodeFile(Model):
    """
    Information about a file or directory on a compute node.

    :param name: Gets or sets the file path.
    :type name: str
    :param url: Gets or sets the URL of the file.
    :type url: str
    :param is_directory: Gets or sets whether the object represents a
     directory.
    :type is_directory: bool
    :param properties: Gets or sets the file properties.
    :type properties: :class:`FileProperties
     <batchserviceclient.models.FileProperties>`
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'is_directory': {'key': 'isDirectory', 'type': 'bool'},
        'properties': {'key': 'properties', 'type': 'FileProperties'},
    }

    def __init__(self, name=None, url=None, is_directory=None, properties=None):
        self.name = name
        self.url = url
        self.is_directory = is_directory
        self.properties = properties
