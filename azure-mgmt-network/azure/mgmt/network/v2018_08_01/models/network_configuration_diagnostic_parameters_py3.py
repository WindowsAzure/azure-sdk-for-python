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


class NetworkConfigurationDiagnosticParameters(Model):
    """Parameters to get network configuration diagnostic.

    All required parameters must be populated in order to send to Azure.

    :param target_resource_id: Required. The ID of the target resource to
     perform network configuration diagnostic. Valid options are VM,
     NetworkInterface, VMSS/NetworkInterface and Application Gateway.
    :type target_resource_id: str
    :param queries: Required. List of traffic queries.
    :type queries: list[~azure.mgmt.network.v2018_08_01.models.TrafficQuery]
    """

    _validation = {
        'target_resource_id': {'required': True},
        'queries': {'required': True},
    }

    _attribute_map = {
        'target_resource_id': {'key': 'targetResourceId', 'type': 'str'},
        'queries': {'key': 'queries', 'type': '[TrafficQuery]'},
    }

    def __init__(self, *, target_resource_id: str, queries, **kwargs) -> None:
        super(NetworkConfigurationDiagnosticParameters, self).__init__(**kwargs)
        self.target_resource_id = target_resource_id
        self.queries = queries
