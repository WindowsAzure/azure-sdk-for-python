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


class AvailableServiceSkuSku(Model):
    """SKU name, tier, etc.

    :param name: The name of the SKU
    :type name: str
    :param family: SKU family
    :type family: str
    :param size: SKU size
    :type size: str
    :param tier: The tier of the SKU, such as "Basic", "General Purpose", or
     "Business Critical"
    :type tier: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'family': {'key': 'family', 'type': 'str'},
        'size': {'key': 'size', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, family: str=None, size: str=None, tier: str=None, **kwargs) -> None:
        super(AvailableServiceSkuSku, self).__init__(**kwargs)
        self.name = name
        self.family = family
        self.size = size
        self.tier = tier
