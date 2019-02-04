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


class AzureSku(Model):
    """Azure SKU definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. SKU name. Possible values include: 'KC8', 'KC16',
     'KS8', 'KS16', 'D13_v2', 'D14_v2', 'L8', 'L16', 'D11_v2', 'D12_v2', 'L4'
    :type name: str or ~azure.mgmt.kusto.models.AzureSkuName
    :param capacity: SKU capacity.
    :type capacity: int
    :ivar tier: Required. SKU tier. Default value: "Standard" .
    :vartype tier: str
    """

    _validation = {
        'name': {'required': True},
        'tier': {'required': True, 'constant': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
        'tier': {'key': 'tier', 'type': 'str'},
    }

    tier = "Standard"

    def __init__(self, *, name, capacity: int=None, **kwargs) -> None:
        super(AzureSku, self).__init__(**kwargs)
        self.name = name
        self.capacity = capacity
