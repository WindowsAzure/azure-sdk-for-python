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


class SubscriptionCreationParameters(Model):
    """Subscription Creation Parameters required to create a new Azure
    subscription.

    :param display_name: The display name of the subscription.
    :type display_name: str
    :param billing_profile_id: The ARM id of the billing profile.
    :type billing_profile_id: str
    :param sku_id: The commerce id of the sku.
    :type sku_id: str
    :param owner: rbac owner of the subscription
    :type owner: ~azure.mgmt.subscription.models.AdPrincipal
    :param additional_parameters: Additional, untyped parameters to support
     custom subscription creation scenarios.
    :type additional_parameters: dict[str, object]
    """

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': 'str'},
        'billing_profile_id': {'key': 'billingProfileId', 'type': 'str'},
        'sku_id': {'key': 'skuId', 'type': 'str'},
        'owner': {'key': 'owner', 'type': 'AdPrincipal'},
        'additional_parameters': {'key': 'additionalParameters', 'type': '{object}'},
    }

    def __init__(self, **kwargs):
        super(SubscriptionCreationParameters, self).__init__(**kwargs)
        self.display_name = kwargs.get('display_name', None)
        self.billing_profile_id = kwargs.get('billing_profile_id', None)
        self.sku_id = kwargs.get('sku_id', None)
        self.owner = kwargs.get('owner', None)
        self.additional_parameters = kwargs.get('additional_parameters', None)
