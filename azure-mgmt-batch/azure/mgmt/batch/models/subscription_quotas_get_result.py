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


class SubscriptionQuotasGetResult(Model):
    """Values returned by the Get Subscription Quotas operation.

    :param account_quota: The number of Batch accounts that may be created
     under the subscription in the specified region.
    :type account_quota: int
    """ 

    _attribute_map = {
        'account_quota': {'key': 'accountQuota', 'type': 'int'},
    }

    def __init__(self, account_quota=None):
        self.account_quota = account_quota
