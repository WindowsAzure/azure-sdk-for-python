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


class CapabilityInformation(Model):
    """Subscription-level properties and limits for Data Lake Store.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar subscription_id: The subscription credentials that uniquely
     identifies the subscription.
    :vartype subscription_id: str
    :ivar state: The subscription state. Possible values include:
     'Registered', 'Suspended', 'Deleted', 'Unregistered', 'Warned'
    :vartype state: str or ~azure.mgmt.datalake.store.models.SubscriptionState
    :ivar max_account_count: The maximum supported number of accounts under
     this subscription.
    :vartype max_account_count: int
    :ivar account_count: The current number of accounts under this
     subscription.
    :vartype account_count: int
    :ivar migration_state: The Boolean value of true or false to indicate the
     maintenance state.
    :vartype migration_state: bool
    """

    _validation = {
        'subscription_id': {'readonly': True},
        'state': {'readonly': True},
        'max_account_count': {'readonly': True},
        'account_count': {'readonly': True},
        'migration_state': {'readonly': True},
    }

    _attribute_map = {
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'max_account_count': {'key': 'maxAccountCount', 'type': 'int'},
        'account_count': {'key': 'accountCount', 'type': 'int'},
        'migration_state': {'key': 'migrationState', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(CapabilityInformation, self).__init__(**kwargs)
        self.subscription_id = None
        self.state = None
        self.max_account_count = None
        self.account_count = None
        self.migration_state = None
