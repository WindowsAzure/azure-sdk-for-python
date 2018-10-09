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


class RemoteLoginInformation(Model):
    """Login details to SSH to a compute node in cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar node_id: Node ID. ID of the compute node.
    :vartype node_id: str
    :ivar ip_address: IP address. Public IP address of the compute node.
    :vartype ip_address: str
    :ivar port: Port. SSH port number of the node.
    :vartype port: float
    """

    _validation = {
        'node_id': {'readonly': True},
        'ip_address': {'readonly': True},
        'port': {'readonly': True},
    }

    _attribute_map = {
        'node_id': {'key': 'nodeId', 'type': 'str'},
        'ip_address': {'key': 'ipAddress', 'type': 'str'},
        'port': {'key': 'port', 'type': 'float'},
    }

    def __init__(self, **kwargs):
        super(RemoteLoginInformation, self).__init__(**kwargs)
        self.node_id = None
        self.ip_address = None
        self.port = None
