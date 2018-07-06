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


class TaskReactivateOptions(Model):
    """Additional parameters for reactivate operation.

    :param timeout: The maximum time that the server can spend processing the
     request, in seconds. The default is 30 seconds. Default value: 30 .
    :type timeout: int
    :param client_request_id: The caller-generated request identity, in the
     form of a GUID with no decoration such as curly braces, e.g.
     9C4D50EE-2D56-4CD3-8152-34347DC9F2B0.
    :type client_request_id: str
    :param return_client_request_id: Whether the server should return the
     client-request-id in the response. Default value: False .
    :type return_client_request_id: bool
    :param ocp_date: The time the request was issued. Client libraries
     typically set this to the current system clock time; set it explicitly if
     you are calling the REST API directly.
    :type ocp_date: datetime
    :param if_match: An ETag value associated with the version of the resource
     known to the client. The operation will be performed only if the
     resource's current ETag on the service exactly matches the value specified
     by the client.
    :type if_match: str
    :param if_none_match: An ETag value associated with the version of the
     resource known to the client. The operation will be performed only if the
     resource's current ETag on the service does not match the value specified
     by the client.
    :type if_none_match: str
    :param if_modified_since: A timestamp indicating the last modified time of
     the resource known to the client. The operation will be performed only if
     the resource on the service has been modified since the specified time.
    :type if_modified_since: datetime
    :param if_unmodified_since: A timestamp indicating the last modified time
     of the resource known to the client. The operation will be performed only
     if the resource on the service has not been modified since the specified
     time.
    :type if_unmodified_since: datetime
    """

    _attribute_map = {
        'timeout': {'key': '', 'type': 'int'},
        'client_request_id': {'key': '', 'type': 'str'},
        'return_client_request_id': {'key': '', 'type': 'bool'},
        'ocp_date': {'key': '', 'type': 'rfc-1123'},
        'if_match': {'key': '', 'type': 'str'},
        'if_none_match': {'key': '', 'type': 'str'},
        'if_modified_since': {'key': '', 'type': 'rfc-1123'},
        'if_unmodified_since': {'key': '', 'type': 'rfc-1123'},
    }

    def __init__(self, **kwargs):
        super(TaskReactivateOptions, self).__init__(**kwargs)
        self.timeout = kwargs.get('timeout', 30)
        self.client_request_id = kwargs.get('client_request_id', None)
        self.return_client_request_id = kwargs.get('return_client_request_id', False)
        self.ocp_date = kwargs.get('ocp_date', None)
        self.if_match = kwargs.get('if_match', None)
        self.if_none_match = kwargs.get('if_none_match', None)
        self.if_modified_since = kwargs.get('if_modified_since', None)
        self.if_unmodified_since = kwargs.get('if_unmodified_since', None)
