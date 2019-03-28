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

from .network_resource_properties_py3 import NetworkResourceProperties


class LocalNetworkResourceProperties(NetworkResourceProperties):
    """Information about a Service Fabric container network local to a single
    Service Fabric cluster.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    :param description: User readable description of the network.
    :type description: str
    :ivar status: Status of the network. Possible values include: 'Unknown',
     'Ready', 'Upgrading', 'Creating', 'Deleting', 'Failed'
    :vartype status: str or ~azure.servicefabric.models.ResourceStatus
    :ivar status_details: Gives additional information about the current
     status of the network.
    :vartype status_details: str
    :param network_address_prefix: Address space for the local container
     network.
    :type network_address_prefix: str
    """

    _validation = {
        'kind': {'required': True},
        'status': {'readonly': True},
        'status_details': {'readonly': True},
    }

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'status_details': {'key': 'statusDetails', 'type': 'str'},
        'network_address_prefix': {'key': 'networkAddressPrefix', 'type': 'str'},
    }

    def __init__(self, *, description: str=None, network_address_prefix: str=None, **kwargs) -> None:
        super(LocalNetworkResourceProperties, self).__init__(description=description, **kwargs)
        self.network_address_prefix = network_address_prefix
        self.kind = 'Local'
