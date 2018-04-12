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


class RepairTaskHistory(Model):
    """A record of the times when the repair task entered each state.
    This type supports the Service Fabric platform; it is not meant to be used
    directly from your code.
    .

    :param created_utc_timestamp: The time when the repair task entered the
     Created state.
    :type created_utc_timestamp: datetime
    :param claimed_utc_timestamp: The time when the repair task entered the
     Claimed state.
    :type claimed_utc_timestamp: datetime
    :param preparing_utc_timestamp: The time when the repair task entered the
     Preparing state.
    :type preparing_utc_timestamp: datetime
    :param approved_utc_timestamp: The time when the repair task entered the
     Approved state
    :type approved_utc_timestamp: datetime
    :param executing_utc_timestamp: The time when the repair task entered the
     Executing state
    :type executing_utc_timestamp: datetime
    :param restoring_utc_timestamp: The time when the repair task entered the
     Restoring state
    :type restoring_utc_timestamp: datetime
    :param completed_utc_timestamp: The time when the repair task entered the
     Completed state
    :type completed_utc_timestamp: datetime
    :param preparing_health_check_start_utc_timestamp: The time when the
     repair task started the health check in the Preparing state.
    :type preparing_health_check_start_utc_timestamp: datetime
    :param preparing_health_check_end_utc_timestamp: The time when the repair
     task completed the health check in the Preparing state.
    :type preparing_health_check_end_utc_timestamp: datetime
    :param restoring_health_check_start_utc_timestamp: The time when the
     repair task started the health check in the Restoring state.
    :type restoring_health_check_start_utc_timestamp: datetime
    :param restoring_health_check_end_utc_timestamp: The time when the repair
     task completed the health check in the Restoring state.
    :type restoring_health_check_end_utc_timestamp: datetime
    """

    _attribute_map = {
        'created_utc_timestamp': {'key': 'CreatedUtcTimestamp', 'type': 'iso-8601'},
        'claimed_utc_timestamp': {'key': 'ClaimedUtcTimestamp', 'type': 'iso-8601'},
        'preparing_utc_timestamp': {'key': 'PreparingUtcTimestamp', 'type': 'iso-8601'},
        'approved_utc_timestamp': {'key': 'ApprovedUtcTimestamp', 'type': 'iso-8601'},
        'executing_utc_timestamp': {'key': 'ExecutingUtcTimestamp', 'type': 'iso-8601'},
        'restoring_utc_timestamp': {'key': 'RestoringUtcTimestamp', 'type': 'iso-8601'},
        'completed_utc_timestamp': {'key': 'CompletedUtcTimestamp', 'type': 'iso-8601'},
        'preparing_health_check_start_utc_timestamp': {'key': 'PreparingHealthCheckStartUtcTimestamp', 'type': 'iso-8601'},
        'preparing_health_check_end_utc_timestamp': {'key': 'PreparingHealthCheckEndUtcTimestamp', 'type': 'iso-8601'},
        'restoring_health_check_start_utc_timestamp': {'key': 'RestoringHealthCheckStartUtcTimestamp', 'type': 'iso-8601'},
        'restoring_health_check_end_utc_timestamp': {'key': 'RestoringHealthCheckEndUtcTimestamp', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(RepairTaskHistory, self).__init__(**kwargs)
        self.created_utc_timestamp = kwargs.get('created_utc_timestamp', None)
        self.claimed_utc_timestamp = kwargs.get('claimed_utc_timestamp', None)
        self.preparing_utc_timestamp = kwargs.get('preparing_utc_timestamp', None)
        self.approved_utc_timestamp = kwargs.get('approved_utc_timestamp', None)
        self.executing_utc_timestamp = kwargs.get('executing_utc_timestamp', None)
        self.restoring_utc_timestamp = kwargs.get('restoring_utc_timestamp', None)
        self.completed_utc_timestamp = kwargs.get('completed_utc_timestamp', None)
        self.preparing_health_check_start_utc_timestamp = kwargs.get('preparing_health_check_start_utc_timestamp', None)
        self.preparing_health_check_end_utc_timestamp = kwargs.get('preparing_health_check_end_utc_timestamp', None)
        self.restoring_health_check_start_utc_timestamp = kwargs.get('restoring_health_check_start_utc_timestamp', None)
        self.restoring_health_check_end_utc_timestamp = kwargs.get('restoring_health_check_end_utc_timestamp', None)
