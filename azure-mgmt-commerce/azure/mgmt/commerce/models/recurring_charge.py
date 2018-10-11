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

from .offer_term_info import OfferTermInfo


class RecurringCharge(OfferTermInfo):
    """Indicates a recurring charge is present for this offer.

    All required parameters must be populated in order to send to Azure.

    :param effective_date: Indicates the date from which the offer term is
     effective.
    :type effective_date: datetime
    :param name: Required. Constant filled by server.
    :type name: str
    :param recurring_charge: The amount of recurring charge as per the offer
     term.
    :type recurring_charge: int
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'effective_date': {'key': 'EffectiveDate', 'type': 'iso-8601'},
        'name': {'key': 'Name', 'type': 'str'},
        'recurring_charge': {'key': 'RecurringCharge', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(RecurringCharge, self).__init__(**kwargs)
        self.recurring_charge = kwargs.get('recurring_charge', None)
        self.name = 'Recurring Charge'
