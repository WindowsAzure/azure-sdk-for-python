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

from .. import models


class VMInsightsOperations(object):
    """VMInsightsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: API version. Constant value: "2018-11-27-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-11-27-preview"

        self.config = config

    def get_onboarding_status(
            self, resource_uri, custom_headers=None, raw=False, **operation_config):
        """Retrieves the VM Insights onboarding status for the specified resource
        or resource scope.

        :param resource_uri: The fully qualified Azure Resource manager
         identifier of the resource, or scope, whose status to retrieve.
        :type resource_uri: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: VMInsightsOnboardingStatus or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.monitor.v2018_11_27_preview.models.VMInsightsOnboardingStatus
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ResponseWithErrorException<azure.mgmt.monitor.v2018_11_27_preview.models.ResponseWithErrorException>`
        """
        # Construct URL
        url = self.get_onboarding_status.metadata['url']
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ResponseWithErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('VMInsightsOnboardingStatus', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_onboarding_status.metadata = {'url': '/{resourceUri}/providers/Microsoft.Insights/vmInsightsOnboardingStatuses/default'}
