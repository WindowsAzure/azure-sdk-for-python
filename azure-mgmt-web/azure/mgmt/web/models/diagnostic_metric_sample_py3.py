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


class DiagnosticMetricSample(Model):
    """Class representing Diagnostic Metric.

    :param timestamp: Time at which metric is measured
    :type timestamp: datetime
    :param role_instance: Role Instance. Null if this counter is not per
     instance
     This is returned and should be whichever instance name we desire to be
     returned
     i.e. CPU and Memory return RDWORKERNAME (LargeDed..._IN_0)
     where RDWORKERNAME is Machine name below and RoleInstance name in
     parenthesis
    :type role_instance: str
    :param total: Total value of the metric. If multiple measurements are made
     this will have sum of all.
    :type total: float
    :param maximum: Maximum of the metric sampled during the time period
    :type maximum: float
    :param minimum: Minimum of the metric sampled during the time period
    :type minimum: float
    :param is_aggregated: Whether the values are aggregates across all workers
     or not
    :type is_aggregated: bool
    """

    _attribute_map = {
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'role_instance': {'key': 'roleInstance', 'type': 'str'},
        'total': {'key': 'total', 'type': 'float'},
        'maximum': {'key': 'maximum', 'type': 'float'},
        'minimum': {'key': 'minimum', 'type': 'float'},
        'is_aggregated': {'key': 'isAggregated', 'type': 'bool'},
    }

    def __init__(self, *, timestamp=None, role_instance: str=None, total: float=None, maximum: float=None, minimum: float=None, is_aggregated: bool=None, **kwargs) -> None:
        super(DiagnosticMetricSample, self).__init__(**kwargs)
        self.timestamp = timestamp
        self.role_instance = role_instance
        self.total = total
        self.maximum = maximum
        self.minimum = minimum
        self.is_aggregated = is_aggregated
