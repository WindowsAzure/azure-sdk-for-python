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


class VirtualNetworkGatewaySku(Model):
    """VirtualNetworkGatewaySku details.

    :param name: Gateway SKU name. Possible values include: 'Basic',
     'HighPerformance', 'Standard', 'UltraPerformance', 'VpnGw1', 'VpnGw2',
     'VpnGw3'
    :type name: str or
     ~azure.mgmt.network.v2018_04_01.models.VirtualNetworkGatewaySkuName
    :param tier: Gateway SKU tier. Possible values include: 'Basic',
     'HighPerformance', 'Standard', 'UltraPerformance', 'VpnGw1', 'VpnGw2',
     'VpnGw3'
    :type tier: str or
     ~azure.mgmt.network.v2018_04_01.models.VirtualNetworkGatewaySkuTier
    :param capacity: The capacity.
    :type capacity: int
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(VirtualNetworkGatewaySku, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.tier = kwargs.get('tier', None)
        self.capacity = kwargs.get('capacity', None)
