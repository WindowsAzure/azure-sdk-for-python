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


class MetricAvailability(Model):
    """Metric availability specifies the time grain (aggregation interval or
    frequency) and the retention period for that time grain.

    :param time_grain: the time grain specifies the aggregation interval for
     the metric. Expressed as a duration 'PT1M', 'P1D', etc.
    :type time_grain: timedelta
    :param retention: the retention period for the metric at the specified
     timegrain.  Expressed as a duration 'PT1M', 'P1D', etc.
    :type retention: timedelta
    """

    _attribute_map = {
        'time_grain': {'key': 'timeGrain', 'type': 'duration'},
        'retention': {'key': 'retention', 'type': 'duration'},
    }

    def __init__(self, *, time_grain=None, retention=None, **kwargs) -> None:
        super(MetricAvailability, self).__init__(**kwargs)
        self.time_grain = time_grain
        self.retention = retention
