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


class TimeSeriesBaseline(Model):
    """The baseline values for a single time series.

    All required parameters must be populated in order to send to Azure.

    :param aggregation: Required. The aggregation type of the metric.
    :type aggregation: str
    :param dimensions: The dimensions of this time series.
    :type dimensions: list[~azure.mgmt.monitor.models.MetricSingleDimension]
    :param timestamps: Required. The list of timestamps of the baselines.
    :type timestamps: list[datetime]
    :param data: Required. The baseline values for each sensitivity.
    :type data: list[~azure.mgmt.monitor.models.SingleBaseline]
    :param metadata: The baseline metadata values.
    :type metadata: list[~azure.mgmt.monitor.models.BaselineMetadata]
    """

    _validation = {
        'aggregation': {'required': True},
        'timestamps': {'required': True},
        'data': {'required': True},
    }

    _attribute_map = {
        'aggregation': {'key': 'aggregation', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[MetricSingleDimension]'},
        'timestamps': {'key': 'timestamps', 'type': '[iso-8601]'},
        'data': {'key': 'data', 'type': '[SingleBaseline]'},
        'metadata': {'key': 'metadata', 'type': '[BaselineMetadata]'},
    }

    def __init__(self, **kwargs):
        super(TimeSeriesBaseline, self).__init__(**kwargs)
        self.aggregation = kwargs.get('aggregation', None)
        self.dimensions = kwargs.get('dimensions', None)
        self.timestamps = kwargs.get('timestamps', None)
        self.data = kwargs.get('data', None)
        self.metadata = kwargs.get('metadata', None)
