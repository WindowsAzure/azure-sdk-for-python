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


class GetObjectsParameters(Model):
    """
    Request parameters for GetObjectsByObjectIds API call

    :param object_ids: Requested object Ids
    :type object_ids: list of str
    :param types: Requested object types
    :type types: list of str
    :param include_directory_object_references: If true, also searches for
     object ids in the partner tenant
    :type include_directory_object_references: bool
    """ 

    _validation = {
        'include_directory_object_references': {'required': True},
    }

    _attribute_map = {
        'object_ids': {'key': 'objectIds', 'type': '[str]'},
        'types': {'key': 'types', 'type': '[str]'},
        'include_directory_object_references': {'key': 'includeDirectoryObjectReferences', 'type': 'bool'},
    }

    def __init__(self, include_directory_object_references, object_ids=None, types=None, **kwargs):
        self.object_ids = object_ids
        self.types = types
        self.include_directory_object_references = include_directory_object_references
