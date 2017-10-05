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


class QueryExperience(Model):
    """Class representing a Traffic Manager HeatMap query experience properties.

    :param endpoint_id: The id of the endpoint from the 'endpoints' array
     which these queries were routed to.
    :type endpoint_id: int
    :param query_count: The number of queries originating from this location.
    :type query_count: int
    :param latency: The latency experienced by queries originating from this
     location.
    :type latency: float
    """

    _validation = {
        'endpoint_id': {'required': True},
        'query_count': {'required': True},
    }

    _attribute_map = {
        'endpoint_id': {'key': 'endpointId', 'type': 'int'},
        'query_count': {'key': 'queryCount', 'type': 'int'},
        'latency': {'key': 'latency', 'type': 'float'},
    }

    def __init__(self, endpoint_id, query_count, latency=None):
        self.endpoint_id = endpoint_id
        self.query_count = query_count
        self.latency = latency
