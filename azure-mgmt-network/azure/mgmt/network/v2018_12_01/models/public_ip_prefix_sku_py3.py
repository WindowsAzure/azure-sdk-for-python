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


class PublicIPPrefixSku(Model):
    """SKU of a public IP prefix.

    :param name: Name of a public IP prefix SKU. Possible values include:
     'Standard'
    :type name: str or
     ~azure.mgmt.network.v2018_12_01.models.PublicIPPrefixSkuName
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, name=None, **kwargs) -> None:
        super(PublicIPPrefixSku, self).__init__(**kwargs)
        self.name = name
