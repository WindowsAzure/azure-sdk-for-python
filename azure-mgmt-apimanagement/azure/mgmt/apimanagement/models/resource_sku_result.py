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


class ResourceSkuResult(Model):
    """Describes an available API Management service SKU.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar resource_type: The type of resource the SKU applies to.
    :vartype resource_type: str
    :ivar sku: Specifies API Management SKU.
    :vartype sku: ~azure.mgmt.apimanagement.models.ResourceSku
    :ivar capacity: Specifies the number of API Management units.
    :vartype capacity: ~azure.mgmt.apimanagement.models.ResourceSkuCapacity
    """

    _validation = {
        'resource_type': {'readonly': True},
        'sku': {'readonly': True},
        'capacity': {'readonly': True},
    }

    _attribute_map = {
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'ResourceSku'},
        'capacity': {'key': 'capacity', 'type': 'ResourceSkuCapacity'},
    }

    def __init__(self, **kwargs):
        super(ResourceSkuResult, self).__init__(**kwargs)
        self.resource_type = None
        self.sku = None
        self.capacity = None
