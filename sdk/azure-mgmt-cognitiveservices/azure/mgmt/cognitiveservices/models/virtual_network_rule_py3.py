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


class VirtualNetworkRule(Model):
    """A rule governing the accessibility from a specific virtual network.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Full resource id of a vnet subnet, such as
     '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/subnet1'.
    :type id: str
    :param state: Gets the state of virtual network rule.
    :type state: str
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
    }

    def __init__(self, *, id: str, state: str=None, **kwargs) -> None:
        super(VirtualNetworkRule, self).__init__(**kwargs)
        self.id = id
        self.state = state
