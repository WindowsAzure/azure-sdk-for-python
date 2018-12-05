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


class SecretValueOperations(object):
    """SecretValueOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: The version of the API. This parameter is required and its value must be `2018-09-01-preview`. Constant value: "2018-09-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-09-01-preview"

        self.config = config

    def create(
            self, resource_group_name, secret_resource_name, secret_value_resource_name, secret_value_resource_description, custom_headers=None, raw=False, **operation_config):
        """Adds the specified value as a new version of the specified secret
        resource.

        Creates a new value of the specified secret resource. The name of the
        value is typically the version identifier. Once created the value
        cannot be changed.

        :param resource_group_name: Azure resource group name
        :type resource_group_name: str
        :param secret_resource_name: The name of the secret resource.
        :type secret_resource_name: str
        :param secret_value_resource_name: The name of the secret resource
         value which is typically the version identifier for the value.
        :type secret_value_resource_name: str
        :param secret_value_resource_description: Description for creating a
         value of a secret resource.
        :type secret_value_resource_description:
         ~azure.mgmt.servicefabricmesh.models.SecretValueResourceDescription
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SecretValueResourceDescription or ClientRawResponse if
         raw=true
        :rtype:
         ~azure.mgmt.servicefabricmesh.models.SecretValueResourceDescription or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabricmesh.models.ErrorModelException>`
        """
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'secretResourceName': self._serialize.url("secret_resource_name", secret_resource_name, 'str', skip_quote=True),
            'secretValueResourceName': self._serialize.url("secret_value_resource_name", secret_value_resource_name, 'str', skip_quote=True)
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
        body_content = self._serialize.body(secret_value_resource_description, 'SecretValueResourceDescription')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201, 202]:
            raise models.ErrorModelException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('SecretValueResourceDescription', response)
        if response.status_code == 201:
            deserialized = self._deserialize('SecretValueResourceDescription', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabricMesh/secrets/{secretResourceName}/values/{secretValueResourceName}'}

    def get(
            self, resource_group_name, secret_resource_name, secret_value_resource_name, custom_headers=None, raw=False, **operation_config):
        """Gets the specified secret value resource.

        Get the information about the specified named secret value resources.
        The information does not include the actual value of the secret.

        :param resource_group_name: Azure resource group name
        :type resource_group_name: str
        :param secret_resource_name: The name of the secret resource.
        :type secret_resource_name: str
        :param secret_value_resource_name: The name of the secret resource
         value which is typically the version identifier for the value.
        :type secret_value_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SecretValueResourceDescription or ClientRawResponse if
         raw=true
        :rtype:
         ~azure.mgmt.servicefabricmesh.models.SecretValueResourceDescription or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabricmesh.models.ErrorModelException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'secretResourceName': self._serialize.url("secret_resource_name", secret_resource_name, 'str', skip_quote=True),
            'secretValueResourceName': self._serialize.url("secret_value_resource_name", secret_value_resource_name, 'str', skip_quote=True)
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
            raise models.ErrorModelException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('SecretValueResourceDescription', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabricMesh/secrets/{secretResourceName}/values/{secretValueResourceName}'}

    def delete(
            self, resource_group_name, secret_resource_name, secret_value_resource_name, custom_headers=None, raw=False, **operation_config):
        """Deletes the specified  value of the named secret resource.

        Deletes the secret value resource identified by the name. The name of
        the resource is typically the version associated with that value.
        Deletion will fail if the specified value is in use.

        :param resource_group_name: Azure resource group name
        :type resource_group_name: str
        :param secret_resource_name: The name of the secret resource.
        :type secret_resource_name: str
        :param secret_value_resource_name: The name of the secret resource
         value which is typically the version identifier for the value.
        :type secret_value_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabricmesh.models.ErrorModelException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'secretResourceName': self._serialize.url("secret_resource_name", secret_resource_name, 'str', skip_quote=True),
            'secretValueResourceName': self._serialize.url("secret_value_resource_name", secret_value_resource_name, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
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
            raise models.ErrorModelException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabricMesh/secrets/{secretResourceName}/values/{secretValueResourceName}'}

    def list(
            self, resource_group_name, secret_resource_name, custom_headers=None, raw=False, **operation_config):
        """List names of all values of the specified secret resource.

        Gets information about all secret value resources of the specified
        secret resource. The information includes the names of the secret value
        resources, but not the actual values.

        :param resource_group_name: Azure resource group name
        :type resource_group_name: str
        :param secret_resource_name: The name of the secret resource.
        :type secret_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of SecretValueResourceDescription
        :rtype:
         ~azure.mgmt.servicefabricmesh.models.SecretValueResourceDescriptionPaged[~azure.mgmt.servicefabricmesh.models.SecretValueResourceDescription]
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabricmesh.models.ErrorModelException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'secretResourceName': self._serialize.url("secret_resource_name", secret_resource_name, 'str', skip_quote=True)
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
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
                raise models.ErrorModelException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.SecretValueResourceDescriptionPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.SecretValueResourceDescriptionPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabricMesh/secrets/{secretResourceName}/values'}

    def list_value(
            self, resource_group_name, secret_resource_name, secret_value_resource_name, custom_headers=None, raw=False, **operation_config):
        """Lists the specified value of the secret resource.

        Lists the decrypted value of the specified named value of the secret
        resource. This is a privileged operation.

        :param resource_group_name: Azure resource group name
        :type resource_group_name: str
        :param secret_resource_name: The name of the secret resource.
        :type secret_resource_name: str
        :param secret_value_resource_name: The name of the secret resource
         value which is typically the version identifier for the value.
        :type secret_value_resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SecretValue or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.servicefabricmesh.models.SecretValue or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorModelException<azure.mgmt.servicefabricmesh.models.ErrorModelException>`
        """
        # Construct URL
        url = self.list_value.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'secretResourceName': self._serialize.url("secret_resource_name", secret_resource_name, 'str', skip_quote=True),
            'secretValueResourceName': self._serialize.url("secret_value_resource_name", secret_value_resource_name, 'str', skip_quote=True)
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
        request = self._client.post(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorModelException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('SecretValue', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_value.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabricMesh/secrets/{secretResourceName}/values/{secretValueResourceName}/list_value'}
