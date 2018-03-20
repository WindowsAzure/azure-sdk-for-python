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


class ServiceSku(Model):
    """An Azure SKU instance.

    :param name: The unique name of the SKU, such as 'P3'
    :type name: str
    :param tier: The tier of the SKU, such as 'Free', 'Basic', 'Standard', or
     'Premium'
    :type tier: str
    :param family: The SKU family, used when the service has multiple
     performance classes within a tier, such as 'A', 'D', etc. for virtual
     machines
    :type family: str
    :param size: The size of the SKU, used when the name alone does not denote
     a service size or when a SKU has multiple performance classes within a
     family, e.g. 'A1' for virtual machines
    :type size: str
    :param capacity: The capacity of the SKU, if it supports scaling
    :type capacity: int
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'family': {'key': 'family', 'type': 'str'},
        'size': {'key': 'size', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, *, name: str=None, tier: str=None, family: str=None, size: str=None, capacity: int=None, **kwargs) -> None:
        super(ServiceSku, self).__init__(**kwargs)
        self.name = name
        self.tier = tier
        self.family = family
        self.size = size
        self.capacity = capacity
