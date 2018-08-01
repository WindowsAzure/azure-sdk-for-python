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

from .proxy_only_resource_py3 import ProxyOnlyResource


class PremierAddOnOffer(ProxyOnlyResource):
    """Premier add-on offer.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param sku: Premier add on SKU.
    :type sku: str
    :param product: Premier add on offer Product.
    :type product: str
    :param vendor: Premier add on offer Vendor.
    :type vendor: str
    :param promo_code_required: <code>true</code> if promotion code is
     required; otherwise, <code>false</code>.
    :type promo_code_required: bool
    :param quota: Premier add on offer Quota.
    :type quota: int
    :param web_hosting_plan_restrictions: App Service plans this offer is
     restricted to. Possible values include: 'None', 'Free', 'Shared', 'Basic',
     'Standard', 'Premium'
    :type web_hosting_plan_restrictions: str or
     ~azure.mgmt.web.models.AppServicePlanRestrictions
    :param privacy_policy_url: Privacy policy URL.
    :type privacy_policy_url: str
    :param legal_terms_url: Legal terms URL.
    :type legal_terms_url: str
    :param marketplace_publisher: Marketplace publisher.
    :type marketplace_publisher: str
    :param marketplace_offer: Marketplace offer.
    :type marketplace_offer: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'sku': {'key': 'properties.sku', 'type': 'str'},
        'product': {'key': 'properties.product', 'type': 'str'},
        'vendor': {'key': 'properties.vendor', 'type': 'str'},
        'promo_code_required': {'key': 'properties.promoCodeRequired', 'type': 'bool'},
        'quota': {'key': 'properties.quota', 'type': 'int'},
        'web_hosting_plan_restrictions': {'key': 'properties.webHostingPlanRestrictions', 'type': 'AppServicePlanRestrictions'},
        'privacy_policy_url': {'key': 'properties.privacyPolicyUrl', 'type': 'str'},
        'legal_terms_url': {'key': 'properties.legalTermsUrl', 'type': 'str'},
        'marketplace_publisher': {'key': 'properties.marketplacePublisher', 'type': 'str'},
        'marketplace_offer': {'key': 'properties.marketplaceOffer', 'type': 'str'},
    }

    def __init__(self, *, kind: str=None, sku: str=None, product: str=None, vendor: str=None, promo_code_required: bool=None, quota: int=None, web_hosting_plan_restrictions=None, privacy_policy_url: str=None, legal_terms_url: str=None, marketplace_publisher: str=None, marketplace_offer: str=None, **kwargs) -> None:
        super(PremierAddOnOffer, self).__init__(kind=kind, **kwargs)
        self.sku = sku
        self.product = product
        self.vendor = vendor
        self.promo_code_required = promo_code_required
        self.quota = quota
        self.web_hosting_plan_restrictions = web_hosting_plan_restrictions
        self.privacy_policy_url = privacy_policy_url
        self.legal_terms_url = legal_terms_url
        self.marketplace_publisher = marketplace_publisher
        self.marketplace_offer = marketplace_offer
