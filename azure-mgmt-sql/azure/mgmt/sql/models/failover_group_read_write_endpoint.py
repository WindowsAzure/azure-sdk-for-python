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


class FailoverGroupReadWriteEndpoint(Model):
    """FailoverGroupReadWriteEndpoint.

    :param failover_policy: Failover policy of the read-write endpoint for the
     failover group. Possible values include: 'Manual', 'Automatic'
    :type failover_policy: str or :class:`ReadWriteEndpointFailoverPolicy
     <azure.mgmt.sql.models.ReadWriteEndpointFailoverPolicy>`
    :param failover_with_data_loss_grace_period_minutes: Grace period before
     failover with data loss is attempted for the read-write endpoint.
    :type failover_with_data_loss_grace_period_minutes: int
    """

    _attribute_map = {
        'failover_policy': {'key': 'failoverPolicy', 'type': 'str'},
        'failover_with_data_loss_grace_period_minutes': {'key': 'failoverWithDataLossGracePeriodMinutes', 'type': 'int'},
    }

    def __init__(self, failover_policy=None, failover_with_data_loss_grace_period_minutes=None):
        self.failover_policy = failover_policy
        self.failover_with_data_loss_grace_period_minutes = failover_with_data_loss_grace_period_minutes
