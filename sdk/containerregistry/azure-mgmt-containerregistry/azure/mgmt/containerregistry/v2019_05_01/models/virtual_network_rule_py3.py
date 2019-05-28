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
    """Virtual network rule.

    All required parameters must be populated in order to send to Azure.

    :param action: The action of virtual network rule. Possible values
     include: 'Allow'. Default value: "Allow" .
    :type action: str or
     ~azure.mgmt.containerregistry.v2019_05_01.models.Action
    :param virtual_network_resource_id: Required. Resource ID of a subnet, for
     example:
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/virtualNetworks/{vnetName}/subnets/{subnetName}.
    :type virtual_network_resource_id: str
    """

    _validation = {
        'virtual_network_resource_id': {'required': True},
    }

    _attribute_map = {
        'action': {'key': 'action', 'type': 'str'},
        'virtual_network_resource_id': {'key': 'id', 'type': 'str'},
    }

    def __init__(self, *, virtual_network_resource_id: str, action="Allow", **kwargs) -> None:
        super(VirtualNetworkRule, self).__init__(**kwargs)
        self.action = action
        self.virtual_network_resource_id = virtual_network_resource_id
