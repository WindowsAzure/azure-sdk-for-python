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
    """The pricing tier (defines a CDN provider, feature list and rate) of the CDN
    profile.

    :param name: Name of the pricing tier. Possible values include:
     'Standard_Verizon', 'Premium_Verizon', 'Custom_Verizon',
     'Standard_Akamai', 'Standard_ChinaCdn', 'Standard_Microsoft'
    :type name: str or ~azure.mgmt.cdn.models.SkuName
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Sku, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
