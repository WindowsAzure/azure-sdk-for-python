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


class LogMetricTrigger(Model):
    """A log metrics trigger descriptor.

    :param threshold_operator: Evaluation operation for Metric -'GreaterThan'
     or 'LessThan' or 'Equal'. Possible values include: 'GreaterThan',
     'LessThan', 'Equal'
    :type threshold_operator: str or
     ~azure.mgmt.monitor.models.ConditionalOperator
    :param threshold: The threshold of the metric trigger.
    :type threshold: float
    :param metric_trigger_type: Metric Trigger Type - 'Consecutive' or
     'Total'. Possible values include: 'Consecutive', 'Total'
    :type metric_trigger_type: str or
     ~azure.mgmt.monitor.models.MetricTriggerType
    :param metric_column: Evaluation of metric on a particular column
    :type metric_column: str
    """

    _attribute_map = {
        'threshold_operator': {'key': 'thresholdOperator', 'type': 'str'},
        'threshold': {'key': 'threshold', 'type': 'float'},
        'metric_trigger_type': {'key': 'metricTriggerType', 'type': 'str'},
        'metric_column': {'key': 'metricColumn', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(LogMetricTrigger, self).__init__(**kwargs)
        self.threshold_operator = kwargs.get('threshold_operator', None)
        self.threshold = kwargs.get('threshold', None)
        self.metric_trigger_type = kwargs.get('metric_trigger_type', None)
        self.metric_column = kwargs.get('metric_column', None)
