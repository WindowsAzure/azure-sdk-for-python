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

from .resource import Resource


class VirtualNetworkRule(Resource):
    """Single item in a List or Get VirtualNetworkRules operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param virtual_network_subnet_id: ARM ID of Virtual Network Subnet
    :type virtual_network_subnet_id: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'virtual_network_subnet_id': {'key': 'properties.virtualNetworkSubnetId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(VirtualNetworkRule, self).__init__(**kwargs)
        self.virtual_network_subnet_id = kwargs.get('virtual_network_subnet_id', None)
