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


class Restriction(Model):
    """The restriction because of which SKU cannot be used.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar type: The type of restrictions. As of now only possible value for
     this is location.
    :vartype type: str
    :ivar values: The value of restrictions. If the restriction type is set to
     location. This would be different locations where the SKU is restricted.
    :vartype values: list[str]
    :param reason_code: The reason for the restriction. As of now this can be
     “QuotaId” or “NotAvailableForSubscription”. Quota Id is set when the SKU
     has requiredQuotas parameter as the subscription does not belong to that
     quota. The “NotAvailableForSubscription” is related to capacity at DC.
     Possible values include: 'QuotaId', 'NotAvailableForSubscription'
    :type reason_code: str or
     ~azure.mgmt.storage.v2018_03_01_preview.models.ReasonCode
    """

    _validation = {
        'type': {'readonly': True},
        'values': {'readonly': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'values': {'key': 'values', 'type': '[str]'},
        'reason_code': {'key': 'reasonCode', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Restriction, self).__init__(**kwargs)
        self.type = None
        self.values = None
        self.reason_code = kwargs.get('reason_code', None)
