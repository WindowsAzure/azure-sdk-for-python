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


class Sku(Model):
    """Billing information related properties of a server.

    :param name: The name of the sku, typically, a letter + Number code, e.g.
     P3.
    :type name: str
    :param tier: The tier of the particular SKU, e.g. Basic. Possible values
     include: 'Basic', 'Standard'
    :type tier: str or ~azure.mgmt.rdbms.postgres.models.SkuTier
    :param capacity: The scale up/out capacity, representing server's compute
     units.
    :type capacity: int
    :param size: The size code, to be interpreted by resource as appropriate.
    :type size: str
    :param family: The family of hardware.
    :type family: str
    """

    _validation = {
        'capacity': {'minimum': 0},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
        'size': {'key': 'size', 'type': 'str'},
        'family': {'key': 'family', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, tier=None, capacity: int=None, size: str=None, family: str=None, **kwargs) -> None:
        super(Sku, self).__init__(**kwargs)
        self.name = name
        self.tier = tier
        self.capacity = capacity
        self.size = size
        self.family = family
