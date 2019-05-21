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


class NetworkAdapterPosition(Model):
    """The network adapter position.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar network_group: The network group. Possible values include: 'None',
     'NonRDMA', 'RDMA'
    :vartype network_group: str or ~azure.mgmt.edgegateway.models.NetworkGroup
    :ivar port: The port.
    :vartype port: int
    """

    _validation = {
        'network_group': {'readonly': True},
        'port': {'readonly': True},
    }

    _attribute_map = {
        'network_group': {'key': 'networkGroup', 'type': 'str'},
        'port': {'key': 'port', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(NetworkAdapterPosition, self).__init__(**kwargs)
        self.network_group = None
        self.port = None
