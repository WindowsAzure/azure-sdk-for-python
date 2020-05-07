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
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling

from .. import models


class IoTHubOperations(object):
    """IoTHubOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config

    def get(
            self, scope, integration_resource_name, custom_headers=None, raw=False, **operation_config):
        """Gets properties of an IoTHub Integration.

        :param scope: The scope of the Digital Twins Integration. The scope
         has to be an IoTHub resource. For example,
         /{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IoTHubs/{resourceName}.
        :type scope: str
        :param integration_resource_name: Name of IoTHub and
         DigitalTwinsInstance integration instance.
        :type integration_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: IntegrationResource or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.digitaltwins.models.IntegrationResource or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.digitaltwins.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str'),
            'integrationResourceName': self._serialize.url("integration_resource_name", integration_resource_name, 'str', max_length=64, min_length=1)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

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
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('IntegrationResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/{scope}/providers/Microsoft.DigitalTwins/integrationResources/{integrationResourceName}'}

    def create_or_update(
            self, scope, integration_resource_name, resource_id=None, custom_headers=None, raw=False, **operation_config):
        """Creates or Updates an IoTHub Integration with DigitalTwinsInstances.

        :param scope: The scope of the Digital Twins Integration. The scope
         has to be an IoTHub resource. For example,
         /{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IoTHubs/{resourceName}.
        :type scope: str
        :param integration_resource_name: Name of IoTHub and
         DigitalTwinsInstance integration instance.
        :type integration_resource_name: str
        :param resource_id: Fully qualified resource identifier of the
         DigitalTwins Azure resource.
        :type resource_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: IntegrationResource or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.digitaltwins.models.IntegrationResource or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.digitaltwins.models.ErrorResponseException>`
        """
        iot_hub_description = models.IntegrationResource(resource_id=resource_id)

        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str'),
            'integrationResourceName': self._serialize.url("integration_resource_name", integration_resource_name, 'str', max_length=64, min_length=1)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

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
        body_content = self._serialize.body(iot_hub_description, 'IntegrationResource')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 201:
            deserialized = self._deserialize('IntegrationResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/{scope}/providers/Microsoft.DigitalTwins/integrationResources/{integrationResourceName}'}


    def _delete_initial(
            self, scope, integration_resource_name, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str'),
            'integrationResourceName': self._serialize.url("integration_resource_name", integration_resource_name, 'str', max_length=64, min_length=1)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

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
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202, 204]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 202:
            deserialized = self._deserialize('IntegrationResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def delete(
            self, scope, integration_resource_name, custom_headers=None, raw=False, polling=True, **operation_config):
        """Deletes a DigitalTwinsInstance link with IoTHub.

        :param scope: The scope of the Digital Twins Integration. The scope
         has to be an IoTHub resource. For example,
         /{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IoTHubs/{resourceName}.
        :type scope: str
        :param integration_resource_name: Name of IoTHub and
         DigitalTwinsInstance integration instance.
        :type integration_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns IntegrationResource or
         ClientRawResponse<IntegrationResource> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.digitaltwins.models.IntegrationResource]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.digitaltwins.models.IntegrationResource]]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.digitaltwins.models.ErrorResponseException>`
        """
        raw_result = self._delete_initial(
            scope=scope,
            integration_resource_name=integration_resource_name,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('IntegrationResource', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    delete.metadata = {'url': '/{scope}/providers/Microsoft.DigitalTwins/integrationResources/{integrationResourceName}'}
