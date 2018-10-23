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


class ConnectionMonitorDestination(Model):
    """Describes the destination of connection monitor.

    :param resource_id: The ID of the resource used as the destination by
     connection monitor.
    :type resource_id: str
    :param address: Address of the connection monitor destination (IP or
     domain name).
    :type address: str
    :param port: The destination port used by connection monitor.
    :type port: int
    """

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'address': {'key': 'address', 'type': 'str'},
        'port': {'key': 'port', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(ConnectionMonitorDestination, self).__init__(**kwargs)
        self.resource_id = kwargs.get('resource_id', None)
        self.address = kwargs.get('address', None)
        self.port = kwargs.get('port', None)
