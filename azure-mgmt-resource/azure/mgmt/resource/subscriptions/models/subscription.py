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


class Subscription(Model):
    """Subscription information.

    :param id: Gets or sets the ID of the resource
     (/subscriptions/SubscriptionId).
    :type id: str
    :param subscription_id: Gets or sets the subscription Id.
    :type subscription_id: str
    :param display_name: Gets or sets the subscription display name
    :type display_name: str
    :param state: Gets or sets the subscription state
    :type state: str
    :param subscription_policies: Gets or sets the subscription policies.
    :type subscription_policies: :class:`SubscriptionPolicies
     <azure.mgmt.resource.subscriptions.models.SubscriptionPolicies>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'subscription_policies': {'key': 'subscriptionPolicies', 'type': 'SubscriptionPolicies'},
    }

    def __init__(self, id=None, subscription_id=None, display_name=None, state=None, subscription_policies=None):
        self.id = id
        self.subscription_id = subscription_id
        self.display_name = display_name
        self.state = state
        self.subscription_policies = subscription_policies
