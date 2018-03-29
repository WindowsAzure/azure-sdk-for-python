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


class WorkbooksOperations(object):
    """WorkbooksOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client Api Version. Constant value: "2015-05-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2015-05-01"

        self.config = config

    def list_by_resource_group(
            self, resource_group_name, location, category, tags=None, can_fetch_content=None, custom_headers=None, raw=False, **operation_config):
        """Get all Workbooks defined within a specified resource group and
        category.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param location: The name of location where workbook is stored.
        :type location: str
        :param category: Category of workbook to return. Possible values
         include: 'workbook', 'TSG', 'performance', 'retention'
        :type category: str or
         ~azure.mgmt.applicationinsights.models.CategoryType
        :param tags: Tags presents on each workbook returned.
        :type tags: list[str]
        :param can_fetch_content: Flag indicating whether or not to return the
         full content for each applicable workbook. If false, only return
         summary content for workbooks.
        :type can_fetch_content: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: WorkbookListResult or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.applicationinsights.models.WorkbookListResult or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.list_by_resource_group.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['location'] = self._serialize.query("location", location, 'str')
        query_parameters['category'] = self._serialize.query("category", category, 'str')
        if tags is not None:
            query_parameters['tags'] = self._serialize.query("tags", tags, '[str]', div=',')
        if can_fetch_content is not None:
            query_parameters['canFetchContent'] = self._serialize.query("can_fetch_content", can_fetch_content, 'bool')
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
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('WorkbookListResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_by_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroup/{resourceGroupName}/providers/microsoft.insights/workbooks'}

    def delete(
            self, resource_group_name, resource_name, location, custom_headers=None, raw=False, **operation_config):
        """Delete a workbook.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param resource_name: The name of the Application Insights component
         resource.
        :type resource_name: str
        :param location: The name of location where workbook is stored.
        :type location: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['location'] = self._serialize.query("location", location, 'str')
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
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200, 204]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroup/{resourceGroupName}/providers/microsoft.insights/workbooks/{resourceName}'}

    def create(
            self, resource_group_name, resource_name, workbook_properties, custom_headers=None, raw=False, **operation_config):
        """Create a new workbook.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param resource_name: The name of the Application Insights component
         resource.
        :type resource_name: str
        :param workbook_properties: Properties that need to be specified to
         create a new workbook.
        :type workbook_properties:
         ~azure.mgmt.applicationinsights.models.Workbook
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Workbook or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.applicationinsights.models.Workbook or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str')
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
        body_content = self._serialize.body(workbook_properties, 'Workbook')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Workbook', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroup/{resourceGroupName}/providers/microsoft.insights/workbooks/{resourceName}'}

    def update(
            self, resource_group_name, resource_name, workbook_properties, custom_headers=None, raw=False, **operation_config):
        """Updates a workbook that has already been added.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param resource_name: The name of the Application Insights component
         resource.
        :type resource_name: str
        :param workbook_properties: Properties that need to be specified to
         create a new workbook.
        :type workbook_properties:
         ~azure.mgmt.applicationinsights.models.Workbook
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Workbook or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.applicationinsights.models.Workbook or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str')
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
        body_content = self._serialize.body(workbook_properties, 'Workbook')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Workbook', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroup/{resourceGroupName}/providers/microsoft.insights/workbooks/{resourceName}'}

    def get(
            self, resource_name, location, custom_headers=None, raw=False, **operation_config):
        """Get a single workbook by its resourceName.

        :param resource_name: The name of the Application Insights component
         resource.
        :type resource_name: str
        :param location: The name of location where workbook is stored.
        :type location: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Workbook or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.applicationinsights.models.Workbook or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['location'] = self._serialize.query("location", location, 'str')
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
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Workbook', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/providers/microsoft.insights/workbooks/{resourceName}'}

    def list_by_source_id(
            self, source_id, category, tags=None, can_fetch_content=None, custom_headers=None, raw=False, **operation_config):
        """Gets a list of workbooks.

        :param source_id: Azure Resource Id that will fetch all linked
         workbooks.
        :type source_id: str
        :param category: Category of workbook to return. Possible values
         include: 'workbook', 'TSG', 'performance', 'retention'
        :type category: str or
         ~azure.mgmt.applicationinsights.models.CategoryType
        :param tags: Tags presents on each workbook returned.
        :type tags: list[str]
        :param can_fetch_content: Flag indicating whether or not to return the
         full content for each applicable workbook. If false, only return
         summary content for workbooks.
        :type can_fetch_content: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype: list[~azure.mgmt.applicationinsights.models.Workbook] or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.list_by_source_id.metadata['url']

        # Construct parameters
        query_parameters = {}
        query_parameters['sourceId'] = self._serialize.query("source_id", source_id, 'str')
        query_parameters['category'] = self._serialize.query("category", category, 'str')
        if tags is not None:
            query_parameters['tags'] = self._serialize.query("tags", tags, '[str]', div=',')
        if can_fetch_content is not None:
            query_parameters['canFetchContent'] = self._serialize.query("can_fetch_content", can_fetch_content, 'bool')
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
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('[Workbook]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_by_source_id.metadata = {'url': '/providers/microsoft.insights/workbooks'}

    def create_link(
            self, resource_group_name, resource_name, source_id, custom_headers=None, raw=False, **operation_config):
        """Create a new workbook link.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param resource_name: The name of the Application Insights component
         resource.
        :type resource_name: str
        :param source_id: Azure Resource Id that will fetch all linked
         workbooks.
        :type source_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.create_link.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['sourceId'] = self._serialize.query("source_id", source_id, 'str')
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
        request = self._client.put(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    create_link.metadata = {'url': '/providers/microsoft.insights/workbooks'}

    def update_link(
            self, resource_group_name, resource_name, source_id, custom_headers=None, raw=False, **operation_config):
        """Updates a workbook that has already been added.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param resource_name: The name of the Application Insights component
         resource.
        :type resource_name: str
        :param source_id: Azure Resource Id that will fetch all linked
         workbooks.
        :type source_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Workbook or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.applicationinsights.models.Workbook or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.update_link.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['sourceId'] = self._serialize.query("source_id", source_id, 'str')
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
        request = self._client.patch(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Workbook', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    update_link.metadata = {'url': '/providers/microsoft.insights/workbooks'}

    def delete_link(
            self, resource_group_name, resource_name, custom_headers=None, raw=False, **operation_config):
        """Delete a workbook.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param resource_name: The name of the Application Insights component
         resource.
        :type resource_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`WorkbookErrorResponseException<azure.mgmt.applicationinsights.models.WorkbookErrorResponseException>`
        """
        # Construct URL
        url = self.delete_link.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str')
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
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200, 204]:
            raise models.WorkbookErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete_link.metadata = {'url': '/providers/microsoft.insights/workbooks'}
