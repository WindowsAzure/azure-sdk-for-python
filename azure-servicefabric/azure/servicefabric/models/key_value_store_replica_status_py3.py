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

from .replica_status_base_py3 import ReplicaStatusBase


class KeyValueStoreReplicaStatus(ReplicaStatusBase):
    """Key value store related information for the replica.

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    :param database_row_count_estimate: Value indicating the estimated number
     of rows in the underlying database.
    :type database_row_count_estimate: str
    :param database_logical_size_estimate: Value indicating the estimated size
     of the underlying database.
    :type database_logical_size_estimate: str
    :param copy_notification_current_key_filter: Value indicating the latest
     key-prefix filter applied to enumeration during the callback. Null if
     there is no pending callback.
    :type copy_notification_current_key_filter: str
    :param copy_notification_current_progress: Value indicating the latest
     number of keys enumerated during the callback. 0 if there is no pending
     callback.
    :type copy_notification_current_progress: str
    :param status_details: Value indicating the current status details of the
     replica.
    :type status_details: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'Kind', 'type': 'str'},
        'database_row_count_estimate': {'key': 'DatabaseRowCountEstimate', 'type': 'str'},
        'database_logical_size_estimate': {'key': 'DatabaseLogicalSizeEstimate', 'type': 'str'},
        'copy_notification_current_key_filter': {'key': 'CopyNotificationCurrentKeyFilter', 'type': 'str'},
        'copy_notification_current_progress': {'key': 'CopyNotificationCurrentProgress', 'type': 'str'},
        'status_details': {'key': 'StatusDetails', 'type': 'str'},
    }

    def __init__(self, *, database_row_count_estimate: str=None, database_logical_size_estimate: str=None, copy_notification_current_key_filter: str=None, copy_notification_current_progress: str=None, status_details: str=None, **kwargs) -> None:
        super(KeyValueStoreReplicaStatus, self).__init__(**kwargs)
        self.database_row_count_estimate = database_row_count_estimate
        self.database_logical_size_estimate = database_logical_size_estimate
        self.copy_notification_current_key_filter = copy_notification_current_key_filter
        self.copy_notification_current_progress = copy_notification_current_progress
        self.status_details = status_details
        self.kind = 'KeyValueStore'
