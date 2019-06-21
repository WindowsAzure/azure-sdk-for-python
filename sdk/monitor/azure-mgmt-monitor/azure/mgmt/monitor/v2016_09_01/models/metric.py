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


class Metric(Model):
    """A set of metric values in a time range.

    All required parameters must be populated in order to send to Azure.

    :param id: the id, resourceId, of the metric.
    :type id: str
    :param type: the resource type of the metric resource.
    :type type: str
    :param name: Required. the name and the display name of the metric, i.e.
     it is localizable string.
    :type name: ~azure.mgmt.monitor.v2016_09_01.models.LocalizableString
    :param unit: Required. the unit of the metric. Possible values include:
     'Count', 'Bytes', 'Seconds', 'CountPerSecond', 'BytesPerSecond',
     'Percent', 'MilliSeconds'
    :type unit: str or ~azure.mgmt.monitor.v2016_09_01.models.Unit
    :param data: Required. Array of data points representing the metric
     values.
    :type data: list[~azure.mgmt.monitor.v2016_09_01.models.MetricValue]
    """

    _validation = {
        'name': {'required': True},
        'unit': {'required': True},
        'data': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'LocalizableString'},
        'unit': {'key': 'unit', 'type': 'Unit'},
        'data': {'key': 'data', 'type': '[MetricValue]'},
    }

    def __init__(self, **kwargs):
        super(Metric, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.type = kwargs.get('type', None)
        self.name = kwargs.get('name', None)
        self.unit = kwargs.get('unit', None)
        self.data = kwargs.get('data', None)
