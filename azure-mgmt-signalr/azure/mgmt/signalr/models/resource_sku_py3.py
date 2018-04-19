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


class ResourceSku(Model):
    """The billing information of the resource.(e.g. basic vs. standard).

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the SKU. This is typically a letter +
     number code, such as A0 or P3.  Required (if sku is specified)
    :type name: str
    :param tier: The tier of this particular SKU. Optional. Possible values
     include: 'Free', 'Basic', 'Premium'
    :type tier: str or ~azure.mgmt.signalr.models.SignalrSkuTier
    :param size: Optional, string. When the name field is the combination of
     tier and some other value, this would be the standalone code.
    :type size: str
    :param family: Optional, string. If the service has different generations
     of hardware, for the same SKU, then that can be captured here.
    :type family: str
    :param capacity: Optional, integer. If the SKU supports scale out/in then
     the capacity integer should be included. If scale out/in is not
     possible for the resource this may be omitted.
    :type capacity: int
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'size': {'key': 'size', 'type': 'str'},
        'family': {'key': 'family', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, *, name: str, tier=None, size: str=None, family: str=None, capacity: int=None, **kwargs) -> None:
        super(ResourceSku, self).__init__(**kwargs)
        self.name = name
        self.tier = tier
        self.size = size
        self.family = family
        self.capacity = capacity
