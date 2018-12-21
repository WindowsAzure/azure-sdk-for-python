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

from .. import models


class MeshServiceReplicaOperations(object):
    """MeshServiceReplicaOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: The version of the API. This parameter is required and its value must be '6.4-preview'. Constant value: "6.4-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config
        self.api_version = "6.4-preview"

    def get(
            self, application_resource_name, service_resource_name, replica_name, custom_headers=None, raw=False, **operation_config):
        """Gets the given replica of the service of an application.

        Gets the information about the service replica with the given name. The
        information include the description and other properties of the service
        replica.

        :param application_resource_name: The identity of the application.
        :type application_resource_name: str
        :param service_resource_name: The identity of the service.
        :type service_resource_name: str
        :param replica_name: Service Fabric replica name.
        :type replica_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ServiceReplicaDescription or ClientRawResponse if raw=true
        :rtype: ~azure.servicefabric.models.ServiceReplicaDescription or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`FabricErrorException<azure.servicefabric.models.FabricErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'applicationResourceName': self._serialize.url("application_resource_name", application_resource_name, 'str', skip_quote=True),
            'serviceResourceName': self._serialize.url("service_resource_name", service_resource_name, 'str', skip_quote=True),
            'replicaName': self._serialize.url("replica_name", replica_name, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.FabricErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ServiceReplicaDescription', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/Resources/Applications/{applicationResourceName}/Services/{serviceResourceName}/Replicas/{replicaName}'}

    def list(
            self, application_resource_name, service_resource_name, custom_headers=None, raw=False, **operation_config):
        """Lists all the replicas of a service.

        Gets the information about all replicas of a service. The information
        include the description and other properties of the service replica.

        :param application_resource_name: The identity of the application.
        :type application_resource_name: str
        :param service_resource_name: The identity of the service.
        :type service_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PagedServiceReplicaDescriptionList or ClientRawResponse if
         raw=true
        :rtype: ~azure.servicefabric.models.PagedServiceReplicaDescriptionList
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`FabricErrorException<azure.servicefabric.models.FabricErrorException>`
        """
        # Construct URL
        url = self.list.metadata['url']
        path_format_arguments = {
            'applicationResourceName': self._serialize.url("application_resource_name", application_resource_name, 'str', skip_quote=True),
            'serviceResourceName': self._serialize.url("service_resource_name", service_resource_name, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.FabricErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PagedServiceReplicaDescriptionList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/Resources/Applications/{applicationResourceName}/Services/{serviceResourceName}/Replicas'}
