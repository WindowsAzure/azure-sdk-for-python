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

from .copy_source import CopySource


class SapOpenHubSource(CopySource):
    """A copy activity source for SAP Business Warehouse Open Hub Destination
    source.

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
    :param exclude_last_request: Whether to exclude the records of the last
     request. The default value is true. Type: boolean (or Expression with
     resultType boolean).
    :type exclude_last_request: object
    :param base_request_id: The ID of request for delta loading. Once it is
     set, only data with requestId larger than the value of this property will
     be retrieved. The default value is 0. Type: integer (or Expression with
     resultType integer ).
    :type base_request_id: object
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
        'exclude_last_request': {'key': 'excludeLastRequest', 'type': 'object'},
        'base_request_id': {'key': 'baseRequestId', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(SapOpenHubSource, self).__init__(**kwargs)
        self.exclude_last_request = kwargs.get('exclude_last_request', None)
        self.base_request_id = kwargs.get('base_request_id', None)
        self.type = 'SapOpenHubSource'
