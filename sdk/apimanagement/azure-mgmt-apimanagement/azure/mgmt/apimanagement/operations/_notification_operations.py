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


class NotificationOperations(object):
    """NotificationOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. Constant value: "2020-06-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2020-06-01-preview"

        self.config = config

    def list_by_service(
            self, resource_group_name, service_name, top=None, skip=None, custom_headers=None, raw=False, **operation_config):
        """Lists a collection of properties defined within a service instance.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param service_name: The name of the API Management service.
        :type service_name: str
        :param top: Number of records to return.
        :type top: int
        :param skip: Number of records to skip.
        :type skip: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of NotificationContract
        :rtype:
         ~azure.mgmt.apimanagement.models.NotificationContractPaged[~azure.mgmt.apimanagement.models.NotificationContract]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.apimanagement.models.ErrorResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_service.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'serviceName': self._serialize.url("service_name", service_name, 'str', max_length=50, min_length=1, pattern=r'^[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', minimum=1)
                if skip is not None:
                    query_parameters['$skip'] = self._serialize.query("skip", skip, 'int', minimum=0)
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
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.NotificationContractPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_by_service.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/notifications'}

    def get(
            self, resource_group_name, service_name, notification_name, custom_headers=None, raw=False, **operation_config):
        """Gets the details of the Notification specified by its identifier.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param service_name: The name of the API Management service.
        :type service_name: str
        :param notification_name: Notification Name Identifier. Possible
         values include: 'RequestPublisherNotificationMessage',
         'PurchasePublisherNotificationMessage',
         'NewApplicationNotificationMessage', 'BCC',
         'NewIssuePublisherNotificationMessage', 'AccountClosedPublisher',
         'QuotaLimitApproachingPublisherNotificationMessage'
        :type notification_name: str or
         ~azure.mgmt.apimanagement.models.NotificationName
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: NotificationContract or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.apimanagement.models.NotificationContract or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.apimanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'serviceName': self._serialize.url("service_name", service_name, 'str', max_length=50, min_length=1, pattern=r'^[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'),
            'notificationName': self._serialize.url("notification_name", notification_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('NotificationContract', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/notifications/{notificationName}'}

    def create_or_update(
            self, resource_group_name, service_name, notification_name, if_match=None, custom_headers=None, raw=False, **operation_config):
        """Create or Update API Management publisher notification.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param service_name: The name of the API Management service.
        :type service_name: str
        :param notification_name: Notification Name Identifier. Possible
         values include: 'RequestPublisherNotificationMessage',
         'PurchasePublisherNotificationMessage',
         'NewApplicationNotificationMessage', 'BCC',
         'NewIssuePublisherNotificationMessage', 'AccountClosedPublisher',
         'QuotaLimitApproachingPublisherNotificationMessage'
        :type notification_name: str or
         ~azure.mgmt.apimanagement.models.NotificationName
        :param if_match: ETag of the Entity. Not required when creating an
         entity, but required when updating an entity.
        :type if_match: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: NotificationContract or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.apimanagement.models.NotificationContract or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.apimanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'serviceName': self._serialize.url("service_name", service_name, 'str', max_length=50, min_length=1, pattern=r'^[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'),
            'notificationName': self._serialize.url("notification_name", notification_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('NotificationContract', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/notifications/{notificationName}'}
