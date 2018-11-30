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


class SubscriptionCreateParameters(Model):
    """Subscription create details.

    All required parameters must be populated in order to send to Azure.

    :param user_id: Required. User (user id path) for whom subscription is
     being created in form /users/{uid}
    :type user_id: str
    :param product_id: Required. Product (product id path) for which
     subscription is being created in form /products/{productId}
    :type product_id: str
    :param display_name: Required. Subscription name.
    :type display_name: str
    :param primary_key: Primary subscription key. If not specified during
     request key will be generated automatically.
    :type primary_key: str
    :param secondary_key: Secondary subscription key. If not specified during
     request key will be generated automatically.
    :type secondary_key: str
    :param state: Initial subscription state. If no value is specified,
     subscription is created with Submitted state. Possible states are * active
     – the subscription is active, * suspended – the subscription is blocked,
     and the subscriber cannot call any APIs of the product, * submitted – the
     subscription request has been made by the developer, but has not yet been
     approved or rejected, * rejected – the subscription request has been
     denied by an administrator, * cancelled – the subscription has been
     cancelled by the developer or administrator, * expired – the subscription
     reached its expiration date and was deactivated. Possible values include:
     'suspended', 'active', 'expired', 'submitted', 'rejected', 'cancelled'
    :type state: str or ~azure.mgmt.apimanagement.models.SubscriptionState
    """

    _validation = {
        'user_id': {'required': True},
        'product_id': {'required': True},
        'display_name': {'required': True, 'max_length': 100, 'min_length': 1},
        'primary_key': {'max_length': 256, 'min_length': 1},
        'secondary_key': {'max_length': 256, 'min_length': 1},
    }

    _attribute_map = {
        'user_id': {'key': 'properties.userId', 'type': 'str'},
        'product_id': {'key': 'properties.productId', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'primary_key': {'key': 'properties.primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'properties.secondaryKey', 'type': 'str'},
        'state': {'key': 'properties.state', 'type': 'SubscriptionState'},
    }

    def __init__(self, **kwargs):
        super(SubscriptionCreateParameters, self).__init__(**kwargs)
        self.user_id = kwargs.get('user_id', None)
        self.product_id = kwargs.get('product_id', None)
        self.display_name = kwargs.get('display_name', None)
        self.primary_key = kwargs.get('primary_key', None)
        self.secondary_key = kwargs.get('secondary_key', None)
        self.state = kwargs.get('state', None)
