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


class AmlComputeNodeInformation(Model):
    """Compute node information related to a AmlCompute.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar node_id: Node ID. ID of the compute node.
    :vartype node_id: str
    :ivar private_ip_address: Private IP address. Private IP address of the
     compute node.
    :vartype private_ip_address: str
    :ivar public_ip_address: Public IP address. Public IP address of the
     compute node.
    :vartype public_ip_address: str
    :ivar port: Port. SSH port number of the node.
    :vartype port: float
    :ivar node_state: State of the compute node. Values are idle, running,
     preparing, unusable, leaving and preempted. Possible values include:
     'idle', 'running', 'preparing', 'unusable', 'leaving', 'preempted'
    :vartype node_state: str or
     ~azure.mgmt.machinelearningservices.models.NodeState
    :ivar run_id: Run ID. ID of the Experiment running on the node, if any
     else null.
    :vartype run_id: str
    """

    _validation = {
        'node_id': {'readonly': True},
        'private_ip_address': {'readonly': True},
        'public_ip_address': {'readonly': True},
        'port': {'readonly': True},
        'node_state': {'readonly': True},
        'run_id': {'readonly': True},
    }

    _attribute_map = {
        'node_id': {'key': 'nodeId', 'type': 'str'},
        'private_ip_address': {'key': 'privateIpAddress', 'type': 'str'},
        'public_ip_address': {'key': 'publicIpAddress', 'type': 'str'},
        'port': {'key': 'port', 'type': 'float'},
        'node_state': {'key': 'nodeState', 'type': 'str'},
        'run_id': {'key': 'runId', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(AmlComputeNodeInformation, self).__init__(**kwargs)
        self.node_id = None
        self.private_ip_address = None
        self.public_ip_address = None
        self.port = None
        self.node_state = None
        self.run_id = None
