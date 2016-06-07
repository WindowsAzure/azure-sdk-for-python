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


class JobResource(Model):
    """
    The Data Lake Analytics U-SQL job resources.

    :param name: Gets or set the name of the resource.
    :type name: str
    :param resource_path: Gets or sets the path to the resource.
    :type resource_path: str
    :param type: Gets or sets the job resource type. Possible values include:
     'VertexResource', 'StatisticsResource'
    :type type: str or :class:`JobResourceType
     <azure.mgmt.datalake.analytics.job.models.JobResourceType>`
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'resource_path': {'key': 'resourcePath', 'type': 'str'},
        'type': {'key': 'type', 'type': 'JobResourceType'},
    }

    def __init__(self, name=None, resource_path=None, type=None):
        self.name = name
        self.resource_path = resource_path
        self.type = type
