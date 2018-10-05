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

from .proxy_resource_py3 import ProxyResource


class InterfaceEndpointProfile(ProxyResource):
    """A interface endpoint profile resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param virtual_network_subnet_id: Required. The ARM resource id of the
     virtual network subnet.
    :type virtual_network_subnet_id: str
    :ivar private_ip: The Private ip associated with the interface endpoint
     profile
    :vartype private_ip: str
    :ivar state: State of the interface endpoint profile. Possible values
     include: 'Initializing', 'InProgress', 'Ready', 'Failed', 'Deleting',
     'Unknown'
    :vartype state: str or
     ~azure.mgmt.sql.models.InterfaceEndpointProfileStateType
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'virtual_network_subnet_id': {'required': True},
        'private_ip': {'readonly': True},
        'state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'virtual_network_subnet_id': {'key': 'properties.virtualNetworkSubnetId', 'type': 'str'},
        'private_ip': {'key': 'properties.privateIp', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'str'},
    }

    def __init__(self, *, virtual_network_subnet_id: str, **kwargs) -> None:
        super(InterfaceEndpointProfile, self).__init__(**kwargs)
        self.virtual_network_subnet_id = virtual_network_subnet_id
        self.private_ip = None
        self.state = None
