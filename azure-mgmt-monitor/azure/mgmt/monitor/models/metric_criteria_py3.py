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


class MetricCriteria(Model):
    """MetricCriteria.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Name of the criteria.
    :type name: str
    :param metric_name: Required. Name of the metric.
    :type metric_name: str
    :param metric_namespace: Namespace of the metric.
    :type metric_namespace: str
    :param operator: Required. the criteria operator.
    :type operator: str
    :param time_aggregation: Required. the criteria time aggregation value.
    :type time_aggregation: str
    :param threshold: Required. the criteria threshold value that activates
     the alert.
    :type threshold: float
    :param dimensions: List of dimension conditions.
    :type dimensions: list[~azure.mgmt.monitor.models.MetricDimension]
    """

    _validation = {
        'name': {'required': True},
        'metric_name': {'required': True},
        'operator': {'required': True},
        'time_aggregation': {'required': True},
        'threshold': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'metric_name': {'key': 'metricName', 'type': 'str'},
        'metric_namespace': {'key': 'metricNamespace', 'type': 'str'},
        'operator': {'key': 'operator', 'type': 'str'},
        'time_aggregation': {'key': 'timeAggregation', 'type': 'str'},
        'threshold': {'key': 'threshold', 'type': 'float'},
        'dimensions': {'key': 'dimensions', 'type': '[MetricDimension]'},
    }

    def __init__(self, *, name: str, metric_name: str, operator: str, time_aggregation: str, threshold: float, metric_namespace: str=None, dimensions=None, **kwargs) -> None:
        super(MetricCriteria, self).__init__(**kwargs)
        self.name = name
        self.metric_name = metric_name
        self.metric_namespace = metric_namespace
        self.operator = operator
        self.time_aggregation = time_aggregation
        self.threshold = threshold
        self.dimensions = dimensions
