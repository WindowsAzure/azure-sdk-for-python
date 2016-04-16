# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class VirtualNetworkGatewaySku(Model):
    """
    VirtualNetworkGatewaySku details

    :param name: Gateway sku name -Basic/HighPerformance/Standard. Possible
     values include: 'Basic', 'HighPerformance', 'Standard'
    :type name: str
    :param tier: Gateway sku tier -Basic/HighPerformance/Standard. Possible
     values include: 'Basic', 'HighPerformance', 'Standard'
    :type tier: str
    :param capacity: The capacity
    :type capacity: int
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'VirtualNetworkGatewaySkuName'},
        'tier': {'key': 'tier', 'type': 'VirtualNetworkGatewaySkuTier'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, name=None, tier=None, capacity=None):
        self.name = name
        self.tier = tier
        self.capacity = capacity
