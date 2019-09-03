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

from .copy_source_py3 import CopySource


class Office365Source(CopySource):
    """A copy activity source for an Office365 service.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param source_retry_count: Source retry count. Type: integer (or
     Expression with resultType integer).
    :type source_retry_count: object
    :param source_retry_wait: Source retry wait. Type: string (or Expression
     with resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type source_retry_wait: object
    :param max_concurrent_connections: The maximum concurrent connection count
     for the source data store. Type: integer (or Expression with resultType
     integer).
    :type max_concurrent_connections: object
    :param type: Required. Constant filled by server.
    :type type: str
    :param allowed_groups: The groups containing all the users. Type: array of
     strings (or Expression with resultType array of strings).
    :type allowed_groups: object
    :param user_scope_filter_uri: The user scope uri. Type: string (or
     Expression with resultType string).
    :type user_scope_filter_uri: object
    :param date_filter_column: The Column to apply the <paramref
     name="StartTime"/> and <paramref name="EndTime"/>. Type: string (or
     Expression with resultType string).
    :type date_filter_column: object
    :param start_time: Start time of the requested range for this dataset.
     Type: string (or Expression with resultType string).
    :type start_time: object
    :param end_time: End time of the requested range for this dataset. Type:
     string (or Expression with resultType string).
    :type end_time: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'source_retry_count': {'key': 'sourceRetryCount', 'type': 'object'},
        'source_retry_wait': {'key': 'sourceRetryWait', 'type': 'object'},
        'max_concurrent_connections': {'key': 'maxConcurrentConnections', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'allowed_groups': {'key': 'allowedGroups', 'type': 'object'},
        'user_scope_filter_uri': {'key': 'userScopeFilterUri', 'type': 'object'},
        'date_filter_column': {'key': 'dateFilterColumn', 'type': 'object'},
        'start_time': {'key': 'startTime', 'type': 'object'},
        'end_time': {'key': 'endTime', 'type': 'object'},
    }

    def __init__(self, *, additional_properties=None, source_retry_count=None, source_retry_wait=None, max_concurrent_connections=None, allowed_groups=None, user_scope_filter_uri=None, date_filter_column=None, start_time=None, end_time=None, **kwargs) -> None:
        super(Office365Source, self).__init__(additional_properties=additional_properties, source_retry_count=source_retry_count, source_retry_wait=source_retry_wait, max_concurrent_connections=max_concurrent_connections, **kwargs)
        self.allowed_groups = allowed_groups
        self.user_scope_filter_uri = user_scope_filter_uri
        self.date_filter_column = date_filter_column
        self.start_time = start_time
        self.end_time = end_time
        self.type = 'Office365Source'
