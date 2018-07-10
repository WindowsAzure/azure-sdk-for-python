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


class BalancePropertiesNewPurchasesDetailsItem(Model):
    """BalancePropertiesNewPurchasesDetailsItem.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: the name of new purchase.
    :vartype name: str
    :ivar value: the value of new purchase.
    :vartype value: decimal.Decimal
    """

    _validation = {
        'name': {'readonly': True},
        'value': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'decimal'},
    }

    def __init__(self):
        super(BalancePropertiesNewPurchasesDetailsItem, self).__init__()
        self.name = None
        self.value = None
