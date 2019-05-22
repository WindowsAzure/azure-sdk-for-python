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


class CheckSkuAvailabilityResult(Model):
    """Check SKU availability result.

    :param kind: The Kind of the resource.
    :type kind: str
    :param type: The Type of the resource.
    :type type: str
    :param sku_name: The SKU of Cognitive Services account.
    :type sku_name: str
    :param sku_available: Indicates the given SKU is available or not.
    :type sku_available: bool
    :param reason: Reason why the SKU is not available.
    :type reason: str
    :param message: Additional error message.
    :type message: str
    """

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'sku_name': {'key': 'skuName', 'type': 'str'},
        'sku_available': {'key': 'skuAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CheckSkuAvailabilityResult, self).__init__(**kwargs)
        self.kind = kwargs.get('kind', None)
        self.type = kwargs.get('type', None)
        self.sku_name = kwargs.get('sku_name', None)
        self.sku_available = kwargs.get('sku_available', None)
        self.reason = kwargs.get('reason', None)
        self.message = kwargs.get('message', None)
