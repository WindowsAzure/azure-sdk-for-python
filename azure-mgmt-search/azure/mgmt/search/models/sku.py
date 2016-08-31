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
    """Defines the SKU of an Azure Search Service, which determines price tier
    and capacity limits.

    :param name: The SKU of the Search service. Possible values include:
     'free', 'standard', 'standard2'
    :type name: str or :class:`SkuType <azure.mgmt.search.models.SkuType>`
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'SkuType'},
    }

    def __init__(self, name=None):
        self.name = name
