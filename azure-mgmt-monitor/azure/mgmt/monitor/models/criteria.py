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


class Criteria(Model):
    """Specifies the criteria for converting log to metric.

    All required parameters must be populated in order to send to Azure.

    :param metric_name: Required. Name of the metric
    :type metric_name: str
    :param dimensions: List of Dimensions for creating metric
    :type dimensions: list[~azure.mgmt.monitor.models.Dimension]
    """

    _validation = {
        'metric_name': {'required': True},
    }

    _attribute_map = {
        'metric_name': {'key': 'metricName', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[Dimension]'},
    }

    def __init__(self, **kwargs):
        super(Criteria, self).__init__(**kwargs)
        self.metric_name = kwargs.get('metric_name', None)
        self.dimensions = kwargs.get('dimensions', None)
