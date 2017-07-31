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

from .proxy_resource import ProxyResource


class VirtualNetworkRule(ProxyResource):
    """A virtual network rule.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param virtual_network_subnet_id: The ARM resource id of the virtual
     network subnet.
    :type virtual_network_subnet_id: str
    :param ignore_vnet_private_access_configuration: Create firewall rule
     before the virtual network has private access enabled.
    :type ignore_vnet_private_access_configuration: bool
    :ivar state: Virtual network rule state. Possible values include:
     'Initializing', 'InProgress', 'Ready', 'Deleting', 'Unknown'
    :vartype state: str or :class:`VirtualNetworkRuleState
     <azure.mgmt.sql.models.VirtualNetworkRuleState>`
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'virtual_network_subnet_id': {'required': True},
        'state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'virtual_network_subnet_id': {'key': 'properties.virtualNetworkSubnetId', 'type': 'str'},
        'ignore_vnet_private_access_configuration': {'key': 'properties.ignoreVnetPrivateAccessConfiguration', 'type': 'bool'},
        'state': {'key': 'properties.state', 'type': 'str'},
    }

    def __init__(self, virtual_network_subnet_id, ignore_vnet_private_access_configuration=None):
        super(VirtualNetworkRule, self).__init__()
        self.virtual_network_subnet_id = virtual_network_subnet_id
        self.ignore_vnet_private_access_configuration = ignore_vnet_private_access_configuration
        self.state = None
