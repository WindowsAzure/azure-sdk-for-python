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

from .connector_read_setting_py3 import ConnectorReadSetting


class HttpReadSetting(ConnectorReadSetting):
    """Sftp read settings.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param type: Required. The read setting type.
    :type type: str
    :param max_concurrent_connections: The maximum concurrent connection count
     for the source data store. Type: integer (or Expression with resultType
     integer).
    :type max_concurrent_connections: object
    :param request_method: The HTTP method used to call the RESTful API. The
     default is GET. Type: string (or Expression with resultType string).
    :type request_method: object
    :param request_body: The HTTP request body to the RESTful API if
     requestMethod is POST. Type: string (or Expression with resultType
     string).
    :type request_body: object
    :param additional_headers: The additional HTTP headers in the request to
     the RESTful API. Type: string (or Expression with resultType string).
    :type additional_headers: object
    :param request_timeout: Specifies the timeout for a HTTP client to get
     HTTP response from HTTP server.
    :type request_timeout: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'type': {'key': 'type', 'type': 'str'},
        'max_concurrent_connections': {'key': 'maxConcurrentConnections', 'type': 'object'},
        'request_method': {'key': 'requestMethod', 'type': 'object'},
        'request_body': {'key': 'requestBody', 'type': 'object'},
        'additional_headers': {'key': 'additionalHeaders', 'type': 'object'},
        'request_timeout': {'key': 'requestTimeout', 'type': 'object'},
    }

    def __init__(self, *, type: str, additional_properties=None, max_concurrent_connections=None, request_method=None, request_body=None, additional_headers=None, request_timeout=None, **kwargs) -> None:
        super(HttpReadSetting, self).__init__(additional_properties=additional_properties, type=type, max_concurrent_connections=max_concurrent_connections, **kwargs)
        self.request_method = request_method
        self.request_body = request_body
        self.additional_headers = additional_headers
        self.request_timeout = request_timeout
