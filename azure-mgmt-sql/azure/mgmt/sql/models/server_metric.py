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


class ServerMetric(Model):
    """Represents Azure SQL server metrics.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar resource_name: The name of the resource.
    :vartype resource_name: str
    :ivar display_name: The metric display name.
    :vartype display_name: str
    :ivar current_value: The current value of the metric.
    :vartype current_value: float
    :ivar limit: The current limit of the metric.
    :vartype limit: float
    :ivar unit: The units of the metric.
    :vartype unit: str
    :ivar next_reset_time: The next reset time for the metric (ISO8601
     format).
    :vartype next_reset_time: datetime
    """

    _validation = {
        'resource_name': {'readonly': True},
        'display_name': {'readonly': True},
        'current_value': {'readonly': True},
        'limit': {'readonly': True},
        'unit': {'readonly': True},
        'next_reset_time': {'readonly': True},
    }

    _attribute_map = {
        'resource_name': {'key': 'resourceName', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'current_value': {'key': 'currentValue', 'type': 'float'},
        'limit': {'key': 'limit', 'type': 'float'},
        'unit': {'key': 'unit', 'type': 'str'},
        'next_reset_time': {'key': 'nextResetTime', 'type': 'iso-8601'},
    }

    def __init__(self):
        self.resource_name = None
        self.display_name = None
        self.current_value = None
        self.limit = None
        self.unit = None
        self.next_reset_time = None
