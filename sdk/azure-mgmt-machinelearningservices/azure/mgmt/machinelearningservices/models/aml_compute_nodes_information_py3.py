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

from .compute_nodes_information_py3 import ComputeNodesInformation


class AmlComputeNodesInformation(ComputeNodesInformation):
    """Compute node information related to a AmlCompute.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar next_link: The continuation token.
    :vartype next_link: str
    :param compute_type: Required. Constant filled by server.
    :type compute_type: str
    :ivar nodes: The collection of returned AmlCompute nodes details.
    :vartype nodes:
     list[~azure.mgmt.machinelearningservices.models.AmlComputeNodeInformation]
    """

    _validation = {
        'next_link': {'readonly': True},
        'compute_type': {'required': True},
        'nodes': {'readonly': True},
    }

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'compute_type': {'key': 'computeType', 'type': 'str'},
        'nodes': {'key': 'nodes', 'type': '[AmlComputeNodeInformation]'},
    }

    def __init__(self, **kwargs) -> None:
        super(AmlComputeNodesInformation, self).__init__(**kwargs)
        self.nodes = None
        self.compute_type = 'AmlCompute'
