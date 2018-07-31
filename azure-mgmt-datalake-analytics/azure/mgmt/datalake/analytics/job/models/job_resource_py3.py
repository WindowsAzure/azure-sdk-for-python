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


class JobResource(Model):
    """The Data Lake Analytics job resources.

    :param name: The name of the resource.
    :type name: str
    :param resource_path: The path to the resource.
    :type resource_path: str
    :param type: The job resource type. Possible values include:
     'VertexResource', 'JobManagerResource', 'StatisticsResource',
     'VertexResourceInUserFolder', 'JobManagerResourceInUserFolder',
     'StatisticsResourceInUserFolder'
    :type type: str or
     ~azure.mgmt.datalake.analytics.job.models.JobResourceType
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'resource_path': {'key': 'resourcePath', 'type': 'str'},
        'type': {'key': 'type', 'type': 'JobResourceType'},
    }

    def __init__(self, *, name: str=None, resource_path: str=None, type=None, **kwargs) -> None:
        super(JobResource, self).__init__(**kwargs)
        self.name = name
        self.resource_path = resource_path
        self.type = type
