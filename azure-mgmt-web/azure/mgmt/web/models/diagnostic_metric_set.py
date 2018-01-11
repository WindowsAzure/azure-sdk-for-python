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


class DiagnosticMetricSet(Model):
    """Class representing Diagnostic Metric information.

    :param name: Name of the metric
    :type name: str
    :param unit: Metric's unit
    :type unit: str
    :param start_time: Start time of the period
    :type start_time: datetime
    :param end_time: End time of the period
    :type end_time: datetime
    :param time_grain: Presented time grain. Supported grains at the moment
     are PT1M, PT1H, P1D
    :type time_grain: str
    :param values: Collection of metric values for the selected period based
     on the
     {Microsoft.Web.Hosting.Administration.DiagnosticMetricSet.TimeGrain}
    :type values: list[~azure.mgmt.web.models.DiagnosticMetricSample]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'time_grain': {'key': 'timeGrain', 'type': 'str'},
        'values': {'key': 'values', 'type': '[DiagnosticMetricSample]'},
    }

    def __init__(self, name=None, unit=None, start_time=None, end_time=None, time_grain=None, values=None):
        self.name = name
        self.unit = unit
        self.start_time = start_time
        self.end_time = end_time
        self.time_grain = time_grain
        self.values = values
