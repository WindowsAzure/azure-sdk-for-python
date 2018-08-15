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


class ConnectionMonitorsQueryResultItem(Model):
    """Results of query particular connection monitor.

    :param resource_id: Connection monitor resource ID.
    :type resource_id: str
    :param report:
    :type report:
     ~azure.mgmt.network.v2018_06_01.models.ConnectionMonitorQueryResult
    """

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'report': {'key': 'report', 'type': 'ConnectionMonitorQueryResult'},
    }

    def __init__(self, *, resource_id: str=None, report=None, **kwargs) -> None:
        super(ConnectionMonitorsQueryResultItem, self).__init__(**kwargs)
        self.resource_id = resource_id
        self.report = report
