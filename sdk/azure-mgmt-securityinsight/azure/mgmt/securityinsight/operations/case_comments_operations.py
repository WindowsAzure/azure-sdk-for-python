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

import uuid
from msrest.pipeline import ClientRawResponse
from msrestazure.azure_exceptions import CloudError

from .. import models


class CaseCommentsOperations(object):
    """CaseCommentsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: API version for the operation. Constant value: "2019-01-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-01-01-preview"

        self.config = config

    def create_comment(
            self, resource_group_name, operational_insights_resource_provider, workspace_name, case_id, case_comment_id, message, custom_headers=None, raw=False, **operation_config):
        """Creates the case comment.

        :param resource_group_name: The name of the resource group within the
         user's subscription. The name is case insensitive.
        :type resource_group_name: str
        :param operational_insights_resource_provider: The namespace of
         workspaces resource provider- Microsoft.OperationalInsights.
        :type operational_insights_resource_provider: str
        :param workspace_name: The name of the workspace.
        :type workspace_name: str
        :param case_id: Case ID
        :type case_id: str
        :param case_comment_id: Case comment ID
        :type case_comment_id: str
        :param message: The comment message
        :type message: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: CaseComment or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.securityinsight.models.CaseComment or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        case_comment = models.CaseComment(message=message)

        # Construct URL
        url = self.create_comment.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str', pattern=r'^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'operationalInsightsResourceProvider': self._serialize.url("operational_insights_resource_provider", operational_insights_resource_provider, 'str'),
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', max_length=90, min_length=1),
            'caseId': self._serialize.url("case_id", case_id, 'str'),
            'caseCommentId': self._serialize.url("case_comment_id", case_comment_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(case_comment, 'CaseComment')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [201]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 201:
            deserialized = self._deserialize('CaseComment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_comment.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{operationalInsightsResourceProvider}/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/cases/{caseId}/comments/{caseCommentId}'}
