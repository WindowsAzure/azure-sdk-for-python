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


class IotDpsSkuDefinition(Model):
    """Available SKUs of tier and units.

    :param name: Sku name. Possible values include: 'S1'
    :type name: str or ~azure.mgmt.iothubprovisioningservices.models.IotDpsSku
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, name=None):
        super(IotDpsSkuDefinition, self).__init__()
        self.name = name
