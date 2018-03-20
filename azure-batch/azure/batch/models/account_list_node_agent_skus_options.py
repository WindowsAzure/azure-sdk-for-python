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


class AccountListNodeAgentSkusOptions(Model):
    """Additional parameters for list_node_agent_skus operation.

    :param filter: An OData $filter clause. For more information on
     constructing this filter, see
     https://docs.microsoft.com/en-us/rest/api/batchservice/odata-filters-in-batch#list-node-agent-skus.
    :type filter: str
    :param max_results: The maximum number of items to return in the response.
     A maximum of 1000 results will be returned. Default value: 1000 .
    :type max_results: int
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
    """

    _attribute_map = {
        'filter': {'key': '', 'type': 'str'},
        'max_results': {'key': '', 'type': 'int'},
        'timeout': {'key': '', 'type': 'int'},
        'client_request_id': {'key': '', 'type': 'str'},
        'return_client_request_id': {'key': '', 'type': 'bool'},
        'ocp_date': {'key': '', 'type': 'rfc-1123'},
    }

    def __init__(self, **kwargs):
        super(AccountListNodeAgentSkusOptions, self).__init__(**kwargs)
        self.filter = kwargs.get('filter', None)
        self.max_results = kwargs.get('max_results', 1000)
        self.timeout = kwargs.get('timeout', 30)
        self.client_request_id = kwargs.get('client_request_id', None)
        self.return_client_request_id = kwargs.get('return_client_request_id', False)
        self.ocp_date = kwargs.get('ocp_date', None)
