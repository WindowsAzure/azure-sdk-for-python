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


class PublicIPAddressSku(Model):
    """SKU of a public IP address.

    :param name: Name of a public IP address SKU. Possible values include:
     'Basic', 'Standard'
    :type name: str or
     ~azure.mgmt.network.v2018_07_01.models.PublicIPAddressSkuName
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, name=None, **kwargs) -> None:
        super(PublicIPAddressSku, self).__init__(**kwargs)
        self.name = name
