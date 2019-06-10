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


class EnabledAzureSKUs(Model):
    """Details about the enabled azure sku.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param sku_id: The sku id.
    :type sku_id: str
    :ivar sku_description: The sku description.
    :vartype sku_description: str
    """

    _validation = {
        'sku_description': {'readonly': True},
    }

    _attribute_map = {
        'sku_id': {'key': 'skuId', 'type': 'str'},
        'sku_description': {'key': 'skuDescription', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EnabledAzureSKUs, self).__init__(**kwargs)
        self.sku_id = kwargs.get('sku_id', None)
        self.sku_description = None
