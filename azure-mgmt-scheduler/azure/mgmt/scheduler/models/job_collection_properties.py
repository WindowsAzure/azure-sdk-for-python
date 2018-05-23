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


class JobCollectionProperties(Model):
    """JobCollectionProperties.

    :param sku: Gets or sets the SKU.
    :type sku: ~azure.mgmt.scheduler.models.Sku
    :param state: Gets or sets the state. Possible values include: 'Enabled',
     'Disabled', 'Suspended', 'Deleted'
    :type state: str or ~azure.mgmt.scheduler.models.JobCollectionState
    :param quota: Gets or sets the job collection quota.
    :type quota: ~azure.mgmt.scheduler.models.JobCollectionQuota
    """

    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'Sku'},
        'state': {'key': 'state', 'type': 'JobCollectionState'},
        'quota': {'key': 'quota', 'type': 'JobCollectionQuota'},
    }

    def __init__(self, sku=None, state=None, quota=None):
        self.sku = sku
        self.state = state
        self.quota = quota
