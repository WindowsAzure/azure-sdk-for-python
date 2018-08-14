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


class ManagementGroupAggregatedCostResult(Resource):
    """A management group aggregated cost resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    :ivar billing_period_id: The id of the billing period resource that the
     aggregated cost belongs to.
    :vartype billing_period_id: str
    :ivar azure_charges: Azure Charges.
    :vartype azure_charges: decimal.Decimal
    :ivar marketplace_charges: Marketplace Charges.
    :vartype marketplace_charges: decimal.Decimal
    :ivar charges_billed_separately: Charges Billed Separately.
    :vartype charges_billed_separately: decimal.Decimal
    :ivar currency: The ISO currency in which the meter is charged, for
     example, USD.
    :vartype currency: str
    :param children: Children of a management group
    :type children:
     list[~azure.mgmt.consumption.models.ManagementGroupAggregatedCostResult]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
        'billing_period_id': {'readonly': True},
        'azure_charges': {'readonly': True},
        'marketplace_charges': {'readonly': True},
        'charges_billed_separately': {'readonly': True},
        'currency': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'billing_period_id': {'key': 'properties.billingPeriodId', 'type': 'str'},
        'azure_charges': {'key': 'properties.azureCharges', 'type': 'decimal'},
        'marketplace_charges': {'key': 'properties.marketplaceCharges', 'type': 'decimal'},
        'charges_billed_separately': {'key': 'properties.chargesBilledSeparately', 'type': 'decimal'},
        'currency': {'key': 'properties.currency', 'type': 'str'},
        'children': {'key': 'properties.children', 'type': '[ManagementGroupAggregatedCostResult]'},
    }

    def __init__(self, *, children=None, **kwargs) -> None:
        super(ManagementGroupAggregatedCostResult, self).__init__(**kwargs)
        self.billing_period_id = None
        self.azure_charges = None
        self.marketplace_charges = None
        self.charges_billed_separately = None
        self.currency = None
        self.children = children
