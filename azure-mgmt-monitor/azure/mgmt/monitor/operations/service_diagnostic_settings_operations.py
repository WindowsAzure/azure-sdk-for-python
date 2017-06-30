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

from msrest.pipeline import ClientRawResponse
from msrestazure.azure_exceptions import CloudError
import uuid

from .. import models


class ServiceDiagnosticSettingsOperations(object):
    """ServiceDiagnosticSettingsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2016-09-01".
    """

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2016-09-01"

        self.config = config

    def get(
            self, resource_uri, custom_headers=None, raw=False, **operation_config):
        """Gets the active diagnostic settings for the specified resource.
        **WARNING**: This method will be deprecated in future releases.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`ServiceDiagnosticSettingsResource
         <azure.mgmt.monitor.models.ServiceDiagnosticSettingsResource>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        :raises:
         :class:`ErrorResponseException<azure.mgmt.monitor.models.ErrorResponseException>`
        """
        # Construct URL
        url = '/{resourceUri}/providers/microsoft.insights/diagnosticSettings/service'
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ServiceDiagnosticSettingsResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create_or_update(
            self, resource_uri, parameters, custom_headers=None, raw=False, **operation_config):
        """Create or update new diagnostic settings for the specified resource.
        **WARNING**: This method will be deprecated in future releases.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :param parameters: Parameters supplied to the operation.
        :type parameters: :class:`ServiceDiagnosticSettingsResource
         <azure.mgmt.monitor.models.ServiceDiagnosticSettingsResource>`
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`ServiceDiagnosticSettingsResource
         <azure.mgmt.monitor.models.ServiceDiagnosticSettingsResource>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/{resourceUri}/providers/microsoft.insights/diagnosticSettings/service'
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(parameters, 'ServiceDiagnosticSettingsResource')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ServiceDiagnosticSettingsResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def update(
            self, resource_uri, service_diagnostic_settings_resource, custom_headers=None, raw=False, **operation_config):
        """Updates an existing ServiceDiagnosticSettingsResource. To update other
        fields use the CreateOrUpdate method. **WARNING**: This method will be
        deprecated in future releases.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :param service_diagnostic_settings_resource: Parameters supplied to
         the operation.
        :type service_diagnostic_settings_resource:
         :class:`ServiceDiagnosticSettingsResourcePatch
         <azure.mgmt.monitor.models.ServiceDiagnosticSettingsResourcePatch>`
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :rtype: :class:`ServiceDiagnosticSettingsResource
         <azure.mgmt.monitor.models.ServiceDiagnosticSettingsResource>`
        :rtype: :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
         if raw=true
        :raises:
         :class:`ErrorResponseException<azure.mgmt.monitor.models.ErrorResponseException>`
        """
        # Construct URL
        url = '/{resourceUri}/providers/microsoft.insights/diagnosticSettings/service'
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(service_diagnostic_settings_resource, 'ServiceDiagnosticSettingsResourcePatch')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ServiceDiagnosticSettingsResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
