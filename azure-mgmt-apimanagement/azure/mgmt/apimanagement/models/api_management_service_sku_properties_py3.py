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


class ApiManagementServiceSkuProperties(Model):
    """API Management service resource SKU properties.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Name of the Sku. Possible values include:
     'Developer', 'Standard', 'Premium', 'Basic', 'Consumption'
    :type name: str or ~azure.mgmt.apimanagement.models.SkuType
    :param capacity: Capacity of the SKU (number of deployed units of the
     SKU).
    :type capacity: int
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, *, name, capacity: int=None, **kwargs) -> None:
        super(ApiManagementServiceSkuProperties, self).__init__(**kwargs)
        self.name = name
        self.capacity = capacity
