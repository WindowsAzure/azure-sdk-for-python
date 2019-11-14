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

from .resource_py3 import Resource


class Policy(Resource):
    """The Policy.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param marketplace_purchases: The marketplace purchases are free, allowed
     or not allowed. Possible values include: 'AllAllowed', 'OnlyFreeAllowed',
     'NotAllowed'
    :type marketplace_purchases: str or
     ~azure.mgmt.billing.models.MarketplacePurchasesPolicy
    :param reservation_purchases: The reservation purchases allowed or not.
     Possible values include: 'Allowed', 'NotAllowed'
    :type reservation_purchases: str or
     ~azure.mgmt.billing.models.ReservationPurchasesPolicy
    :param view_charges: Who can view charges. Possible values include:
     'None', 'SubscriptionOwner'
    :type view_charges: str or ~azure.mgmt.billing.models.ViewChargesPolicy
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'marketplace_purchases': {'key': 'properties.marketplacePurchases', 'type': 'str'},
        'reservation_purchases': {'key': 'properties.reservationPurchases', 'type': 'str'},
        'view_charges': {'key': 'properties.viewCharges', 'type': 'str'},
    }

    def __init__(self, *, marketplace_purchases=None, reservation_purchases=None, view_charges=None, **kwargs) -> None:
        super(Policy, self).__init__(**kwargs)
        self.marketplace_purchases = marketplace_purchases
        self.reservation_purchases = reservation_purchases
        self.view_charges = view_charges
