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


class MultiMetricCriteria(Model):
    """The types of conditions for a multi resource alert.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: MetricCriteria, DynamicMetricCriteria

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param name: Required. Name of the criteria.
    :type name: str
    :param metric_name: Required. Name of the metric.
    :type metric_name: str
    :param metric_namespace: Namespace of the metric.
    :type metric_namespace: str
    :param time_aggregation: Required. the criteria time aggregation types.
    :type time_aggregation: object
    :param dimensions: List of dimension conditions.
    :type dimensions:
     list[~azure.mgmt.monitor.v2018_03_01.models.MetricDimension]
    :param criterion_type: Required. Constant filled by server.
    :type criterion_type: str
    """

    _validation = {
        'name': {'required': True},
        'metric_name': {'required': True},
        'time_aggregation': {'required': True},
        'criterion_type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'name': {'key': 'name', 'type': 'str'},
        'metric_name': {'key': 'metricName', 'type': 'str'},
        'metric_namespace': {'key': 'metricNamespace', 'type': 'str'},
        'time_aggregation': {'key': 'timeAggregation', 'type': 'object'},
        'dimensions': {'key': 'dimensions', 'type': '[MetricDimension]'},
        'criterion_type': {'key': 'criterionType', 'type': 'str'},
    }

    _subtype_map = {
        'criterion_type': {'StaticThresholdCriterion': 'MetricCriteria', 'DynamicThresholdCriterion': 'DynamicMetricCriteria'}
    }

    def __init__(self, *, name: str, metric_name: str, time_aggregation, additional_properties=None, metric_namespace: str=None, dimensions=None, **kwargs) -> None:
        super(MultiMetricCriteria, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.name = name
        self.metric_name = metric_name
        self.metric_namespace = metric_namespace
        self.time_aggregation = time_aggregation
        self.dimensions = dimensions
        self.criterion_type = None
