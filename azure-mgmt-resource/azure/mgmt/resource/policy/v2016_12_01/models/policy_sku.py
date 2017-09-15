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


class PolicySku(Model):
    """The policy sku.

    :param name: The name of the policy sku. Possible values are A0 and A1.
    :type name: str
    :param tier: The policy sku tier. Possible values are Free and Standard.
    :type tier: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
    }

    def __init__(self, name, tier=None):
        self.name = name
        self.tier = tier
