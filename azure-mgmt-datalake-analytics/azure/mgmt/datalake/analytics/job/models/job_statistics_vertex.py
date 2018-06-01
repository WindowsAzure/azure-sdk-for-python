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


class JobStatisticsVertex(Model):
    """The detailed information for a vertex.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: The name of the vertex.
    :vartype name: str
    :ivar vertex_id: The id of the vertex.
    :vartype vertex_id: str
    :ivar execution_time: The amount of execution time of the vertex.
    :vartype execution_time: timedelta
    :ivar data_read: The amount of data read of the vertex, in bytes.
    :vartype data_read: long
    :ivar peak_mem_usage: The amount of peak memory usage of the vertex, in
     bytes.
    :vartype peak_mem_usage: long
    """

    _validation = {
        'name': {'readonly': True},
        'vertex_id': {'readonly': True},
        'execution_time': {'readonly': True},
        'data_read': {'readonly': True},
        'peak_mem_usage': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'vertex_id': {'key': 'vertexId', 'type': 'str'},
        'execution_time': {'key': 'executionTime', 'type': 'duration'},
        'data_read': {'key': 'dataRead', 'type': 'long'},
        'peak_mem_usage': {'key': 'peakMemUsage', 'type': 'long'},
    }

    def __init__(self):
        super(JobStatisticsVertex, self).__init__()
        self.name = None
        self.vertex_id = None
        self.execution_time = None
        self.data_read = None
        self.peak_mem_usage = None
