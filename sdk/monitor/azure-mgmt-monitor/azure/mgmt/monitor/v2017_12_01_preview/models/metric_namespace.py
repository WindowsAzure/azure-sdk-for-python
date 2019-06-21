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


class MetricNamespace(Model):
    """Metric namespace class specifies the metadata for a metric namespace.

    :param id: The ID of the metricNamespace.
    :type id: str
    :param type: The type of the namespace.
    :type type: str
    :param name: The name of the namespace.
    :type name: str
    :param properties: Properties which include the fully qualified namespace
     name.
    :type properties:
     ~azure.mgmt.monitor.v2017_12_01_preview.models.MetricNamespaceName
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'MetricNamespaceName'},
    }

    def __init__(self, **kwargs):
        super(MetricNamespace, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.type = kwargs.get('type', None)
        self.name = kwargs.get('name', None)
        self.properties = kwargs.get('properties', None)
