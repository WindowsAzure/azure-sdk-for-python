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


class ApplicationGatewaySku(Model):
    """SKU of application gateway.

    :param name: Name of an application gateway SKU. Possible values are:
     'Standard_Small', 'Standard_Medium', 'Standard_Large', 'WAF_Medium', and
     'WAF_Large'. Possible values include: 'Standard_Small', 'Standard_Medium',
     'Standard_Large'
    :type name: str or
     ~azure.mgmt.network.v2015_06_15.models.ApplicationGatewaySkuName
    :param tier: Tier of an application gateway. Possible values include:
     'Standard'
    :type tier: str or
     ~azure.mgmt.network.v2015_06_15.models.ApplicationGatewayTier
    :param capacity: Capacity (instance count) of an application gateway.
    :type capacity: int
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, name=None, tier=None, capacity=None):
        super(ApplicationGatewaySku, self).__init__()
        self.name = name
        self.tier = tier
        self.capacity = capacity
