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


class RestSource(CopySource):
    """A copy activity Rest service source.

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
     connectioned to source data store. Type: integer (or Expression with
     resultType integer).
    :type max_concurrent_connections: object
    :param type: Required. Constant filled by server.
    :type type: str
    :param http_request_timeout: The timeout (TimeSpan) to get an HTTP
     response. It is the timeout to get a response, not the timeout to read
     response data. Default value: 00:01:40. Type: string (or Expression with
     resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type http_request_timeout: object
    :param request_interval: The time to await before sending next page
     request.
    :type request_interval: object
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
        'http_request_timeout': {'key': 'httpRequestTimeout', 'type': 'object'},
        'request_interval': {'key': 'requestInterval', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(RestSource, self).__init__(**kwargs)
        self.http_request_timeout = kwargs.get('http_request_timeout', None)
        self.request_interval = kwargs.get('request_interval', None)
        self.type = 'RestSource'
