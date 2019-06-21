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


class DataSource(Model):
    """Data source object contains configuration to collect telemetry and one or
    more sinks to send that telemetry data to.

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Datasource kind. Possible values include:
     'PerformanceCounter', 'ETWProviders', 'WindowsEventLogs'
    :type kind: str or ~azure.mgmt.monitor.v2018_06_01_preview.models.enum
    :param configuration: Required.
    :type configuration:
     ~azure.mgmt.monitor.v2018_06_01_preview.models.DataSourceConfiguration
    :param sinks: Required.
    :type sinks:
     list[~azure.mgmt.monitor.v2018_06_01_preview.models.SinkConfiguration]
    """

    _validation = {
        'kind': {'required': True},
        'configuration': {'required': True},
        'sinks': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
        'configuration': {'key': 'configuration', 'type': 'DataSourceConfiguration'},
        'sinks': {'key': 'sinks', 'type': '[SinkConfiguration]'},
    }

    def __init__(self, **kwargs):
        super(DataSource, self).__init__(**kwargs)
        self.kind = kwargs.get('kind', None)
        self.configuration = kwargs.get('configuration', None)
        self.sinks = kwargs.get('sinks', None)
