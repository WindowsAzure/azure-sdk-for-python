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


class RateCardQueryParameters(Model):
    """Parameters that are used in the odata $filter query parameter for providing
    RateCard information.

    All required parameters must be populated in order to send to Azure.

    :param offer_durable_id: Required. The Offer ID parameter consists of the
     'MS-AZR-' prefix, plus the Offer ID number (e.g., MS-AZR-0026P). See
     https://azure.microsoft.com/en-us/support/legal/offer-details/ for more
     information on the list of available Offer IDs, country/region
     availability, and billing currency.
    :type offer_durable_id: str
    :param currency: Required. The currency in which the rates need to be
     provided.
    :type currency: str
    :param locale: Required. The culture in which the resource metadata needs
     to be localized.
    :type locale: str
    :param region_info: Required. 2 letter ISO code where the offer was
     purchased.
    :type region_info: str
    """

    _validation = {
        'offer_durable_id': {'required': True, 'pattern': r'^MS-AZR-\d{4}P(-\d{4}P)*$'},
        'currency': {'required': True},
        'locale': {'required': True},
        'region_info': {'required': True},
    }

    _attribute_map = {
        'offer_durable_id': {'key': 'OfferDurableId', 'type': 'str'},
        'currency': {'key': 'Currency', 'type': 'str'},
        'locale': {'key': 'Locale', 'type': 'str'},
        'region_info': {'key': 'RegionInfo', 'type': 'str'},
    }

    def __init__(self, *, offer_durable_id: str, currency: str, locale: str, region_info: str, **kwargs) -> None:
        super(RateCardQueryParameters, self).__init__(**kwargs)
        self.offer_durable_id = offer_durable_id
        self.currency = currency
        self.locale = locale
        self.region_info = region_info
