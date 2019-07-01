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
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling

from .. import models


class ResourcesOperations(object):
    """ResourcesOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2016-02-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2016-02-01"

        self.config = config


    def _move_resources_initial(
            self, source_resource_group_name, resources=None, target_resource_group=None, custom_headers=None, raw=False, **operation_config):
        parameters = models.ResourcesMoveInfo(resources=resources, target_resource_group=target_resource_group)

        # Construct URL
        url = self.move_resources.metadata['url']
        path_format_arguments = {
            'sourceResourceGroupName': self._serialize.url("source_resource_group_name", source_resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        body_content = self._serialize.body(parameters, 'ResourcesMoveInfo')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [202, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def move_resources(
            self, source_resource_group_name, resources=None, target_resource_group=None, custom_headers=None, raw=False, polling=True, **operation_config):
        """Move resources from one resource group to another. The resources being
        moved should all be in the same resource group.

        :param source_resource_group_name: Source resource group name.
        :type source_resource_group_name: str
        :param resources: The ids of the resources.
        :type resources: list[str]
        :param target_resource_group: The target resource group.
        :type target_resource_group: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns None or
         ClientRawResponse<None> if raw==True
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[None]]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._move_resources_initial(
            source_resource_group_name=source_resource_group_name,
            resources=resources,
            target_resource_group=target_resource_group,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            if raw:
                client_raw_response = ClientRawResponse(None, response)
                return client_raw_response

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    move_resources.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{sourceResourceGroupName}/moveResources'}

    def list(
            self, filter=None, expand=None, top=None, custom_headers=None, raw=False, **operation_config):
        """Get all of the resources under a subscription.

        :param filter: The filter to apply on the operation.
        :type filter: str
        :param expand: The $expand query parameter.
        :type expand: str
        :param top: Query parameters. If null is passed returns all resource
         groups.
        :type top: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of GenericResource
        :rtype:
         ~azure.mgmt.resource.resources.v2016_02_01.models.GenericResourcePaged[~azure.mgmt.resource.resources.v2016_02_01.models.GenericResource]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if expand is not None:
                    query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
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
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.GenericResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resources'}

    def check_existence(
            self, resource_group_name, resource_provider_namespace, parent_resource_path, resource_type, resource_name, api_version, custom_headers=None, raw=False, **operation_config):
        """Checks whether resource exists.

        :param resource_group_name: The name of the resource group. The name
         is case insensitive.
        :type resource_group_name: str
        :param resource_provider_namespace: Resource identity.
        :type resource_provider_namespace: str
        :param parent_resource_path: Resource identity.
        :type parent_resource_path: str
        :param resource_type: Resource identity.
        :type resource_type: str
        :param resource_name: Resource identity.
        :type resource_name: str
        :param api_version:
        :type api_version: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: bool or ClientRawResponse if raw=true
        :rtype: bool or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.check_existence.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'resourceProviderNamespace': self._serialize.url("resource_provider_namespace", resource_provider_namespace, 'str'),
            'parentResourcePath': self._serialize.url("parent_resource_path", parent_resource_path, 'str', skip_quote=True),
            'resourceType': self._serialize.url("resource_type", resource_type, 'str', skip_quote=True),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.head(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [204, 404]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = (response.status_code == 204)
        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response
        return deserialized
    check_existence.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}'}

    def delete(
            self, resource_group_name, resource_provider_namespace, parent_resource_path, resource_type, resource_name, api_version, custom_headers=None, raw=False, **operation_config):
        """Delete resource and all of its resources. .

        :param resource_group_name: The name of the resource group. The name
         is case insensitive.
        :type resource_group_name: str
        :param resource_provider_namespace: Resource identity.
        :type resource_provider_namespace: str
        :param parent_resource_path: Resource identity.
        :type parent_resource_path: str
        :param resource_type: Resource identity.
        :type resource_type: str
        :param resource_name: Resource identity.
        :type resource_name: str
        :param api_version:
        :type api_version: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'resourceProviderNamespace': self._serialize.url("resource_provider_namespace", resource_provider_namespace, 'str'),
            'parentResourcePath': self._serialize.url("parent_resource_path", parent_resource_path, 'str', skip_quote=True),
            'resourceType': self._serialize.url("resource_type", resource_type, 'str', skip_quote=True),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}'}

    def create_or_update(
            self, resource_group_name, resource_provider_namespace, parent_resource_path, resource_type, resource_name, api_version, parameters, custom_headers=None, raw=False, **operation_config):
        """Create a resource.

        :param resource_group_name: The name of the resource group. The name
         is case insensitive.
        :type resource_group_name: str
        :param resource_provider_namespace: Resource identity.
        :type resource_provider_namespace: str
        :param parent_resource_path: Resource identity.
        :type parent_resource_path: str
        :param resource_type: Resource identity.
        :type resource_type: str
        :param resource_name: Resource identity.
        :type resource_name: str
        :param api_version:
        :type api_version: str
        :param parameters: Create or update resource parameters.
        :type parameters:
         ~azure.mgmt.resource.resources.v2016_02_01.models.GenericResource
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: GenericResource or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.resource.resources.v2016_02_01.models.GenericResource or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'resourceProviderNamespace': self._serialize.url("resource_provider_namespace", resource_provider_namespace, 'str'),
            'parentResourcePath': self._serialize.url("parent_resource_path", parent_resource_path, 'str', skip_quote=True),
            'resourceType': self._serialize.url("resource_type", resource_type, 'str', skip_quote=True),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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
        body_content = self._serialize.body(parameters, 'GenericResource')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('GenericResource', response)
        if response.status_code == 201:
            deserialized = self._deserialize('GenericResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}'}


    def _update_initial(
            self, resource_group_name, resource_provider_namespace, parent_resource_path, resource_type, resource_name, api_version, parameters, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'resourceProviderNamespace': self._serialize.url("resource_provider_namespace", resource_provider_namespace, 'str'),
            'parentResourcePath': self._serialize.url("parent_resource_path", parent_resource_path, 'str', skip_quote=True),
            'resourceType': self._serialize.url("resource_type", resource_type, 'str', skip_quote=True),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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
        body_content = self._serialize.body(parameters, 'GenericResource')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('GenericResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def update(
            self, resource_group_name, resource_provider_namespace, parent_resource_path, resource_type, resource_name, api_version, parameters, custom_headers=None, raw=False, polling=True, **operation_config):
        """Updates a resource.

        :param resource_group_name: The name of the resource group for the
         resource. The name is case insensitive.
        :type resource_group_name: str
        :param resource_provider_namespace: The namespace of the resource
         provider.
        :type resource_provider_namespace: str
        :param parent_resource_path: The parent resource identity.
        :type parent_resource_path: str
        :param resource_type: The resource type of the resource to update.
        :type resource_type: str
        :param resource_name: The name of the resource to update.
        :type resource_name: str
        :param api_version: The API version to use for the operation.
        :type api_version: str
        :param parameters: Parameters for updating the resource.
        :type parameters:
         ~azure.mgmt.resource.resources.v2016_02_01.models.GenericResource
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns GenericResource or
         ClientRawResponse<GenericResource> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.resource.resources.v2016_02_01.models.GenericResource]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.resource.resources.v2016_02_01.models.GenericResource]]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = self._update_initial(
            resource_group_name=resource_group_name,
            resource_provider_namespace=resource_provider_namespace,
            parent_resource_path=parent_resource_path,
            resource_type=resource_type,
            resource_name=resource_name,
            api_version=api_version,
            parameters=parameters,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('GenericResource', response)

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
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}'}

    def get(
            self, resource_group_name, resource_provider_namespace, parent_resource_path, resource_type, resource_name, api_version, custom_headers=None, raw=False, **operation_config):
        """Returns a resource belonging to a resource group.

        :param resource_group_name: The name of the resource group. The name
         is case insensitive.
        :type resource_group_name: str
        :param resource_provider_namespace: Resource identity.
        :type resource_provider_namespace: str
        :param parent_resource_path: Resource identity.
        :type parent_resource_path: str
        :param resource_type: Resource identity.
        :type resource_type: str
        :param resource_name: Resource identity.
        :type resource_name: str
        :param api_version:
        :type api_version: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: GenericResource or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.resource.resources.v2016_02_01.models.GenericResource or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'resourceProviderNamespace': self._serialize.url("resource_provider_namespace", resource_provider_namespace, 'str'),
            'parentResourcePath': self._serialize.url("parent_resource_path", parent_resource_path, 'str', skip_quote=True),
            'resourceType': self._serialize.url("resource_type", resource_type, 'str', skip_quote=True),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

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
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('GenericResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}'}
