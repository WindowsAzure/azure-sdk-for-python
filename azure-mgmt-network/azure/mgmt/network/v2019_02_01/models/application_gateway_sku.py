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
    """SKU of an application gateway.

    :param name: Name of an application gateway SKU. Possible values include:
     'Standard_Small', 'Standard_Medium', 'Standard_Large', 'WAF_Medium',
     'WAF_Large', 'Standard_v2', 'WAF_v2'
    :type name: str or
     ~azure.mgmt.network.v2019_02_01.models.ApplicationGatewaySkuName
    :param tier: Tier of an application gateway. Possible values include:
     'Standard', 'WAF', 'Standard_v2', 'WAF_v2'
    :type tier: str or
     ~azure.mgmt.network.v2019_02_01.models.ApplicationGatewayTier
    :param capacity: Capacity (instance count) of an application gateway.
    :type capacity: int
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(ApplicationGatewaySku, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.tier = kwargs.get('tier', None)
        self.capacity = kwargs.get('capacity', None)
