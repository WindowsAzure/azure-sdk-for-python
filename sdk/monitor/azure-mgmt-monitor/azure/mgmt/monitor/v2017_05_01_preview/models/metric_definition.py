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


class MetricDefinition(Model):
    """Metric definition class specifies the metadata for a metric.

    :param is_dimension_required: Flag to indicate whether the dimension is
     required.
    :type is_dimension_required: bool
    :param resource_id: the resource identifier of the resource that emitted
     the metric.
    :type resource_id: str
    :param name: the name and the display name of the metric, i.e. it is a
     localizable string.
    :type name:
     ~azure.mgmt.monitor.v2017_05_01_preview.models.LocalizableString
    :param unit: the unit of the metric. Possible values include: 'Count',
     'Bytes', 'Seconds', 'CountPerSecond', 'BytesPerSecond', 'Percent',
     'MilliSeconds', 'ByteSeconds', 'Unspecified'
    :type unit: str or ~azure.mgmt.monitor.v2017_05_01_preview.models.Unit
    :param primary_aggregation_type: the primary aggregation type value
     defining how to use the values for display. Possible values include:
     'None', 'Average', 'Count', 'Minimum', 'Maximum', 'Total'
    :type primary_aggregation_type: str or
     ~azure.mgmt.monitor.v2017_05_01_preview.models.AggregationType
    :param metric_availabilities: the collection of what aggregation intervals
     are available to be queried.
    :type metric_availabilities:
     list[~azure.mgmt.monitor.v2017_05_01_preview.models.MetricAvailability]
    :param id: the resource identifier of the metric definition.
    :type id: str
    :param dimensions: the name and the display name of the dimension, i.e. it
     is a localizable string.
    :type dimensions:
     list[~azure.mgmt.monitor.v2017_05_01_preview.models.LocalizableString]
    """

    _attribute_map = {
        'is_dimension_required': {'key': 'isDimensionRequired', 'type': 'bool'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'name': {'key': 'name', 'type': 'LocalizableString'},
        'unit': {'key': 'unit', 'type': 'Unit'},
        'primary_aggregation_type': {'key': 'primaryAggregationType', 'type': 'AggregationType'},
        'metric_availabilities': {'key': 'metricAvailabilities', 'type': '[MetricAvailability]'},
        'id': {'key': 'id', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[LocalizableString]'},
    }

    def __init__(self, **kwargs):
        super(MetricDefinition, self).__init__(**kwargs)
        self.is_dimension_required = kwargs.get('is_dimension_required', None)
        self.resource_id = kwargs.get('resource_id', None)
        self.name = kwargs.get('name', None)
        self.unit = kwargs.get('unit', None)
        self.primary_aggregation_type = kwargs.get('primary_aggregation_type', None)
        self.metric_availabilities = kwargs.get('metric_availabilities', None)
        self.id = kwargs.get('id', None)
        self.dimensions = kwargs.get('dimensions', None)
