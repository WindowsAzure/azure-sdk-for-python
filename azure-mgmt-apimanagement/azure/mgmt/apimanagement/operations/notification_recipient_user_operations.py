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


class NotificationRecipientUserOperations(object):
    """NotificationRecipientUserOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. Constant value: "2019-01-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-01-01"

        self.config = config

    def list_by_notification(
            self, resource_group_name, service_name, notification_name, custom_headers=None, raw=False, **operation_config):
        """Gets the list of the Notification Recipient User subscribed to the
        notification.

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
        :return: RecipientUserCollection or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.apimanagement.models.RecipientUserCollection or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.apimanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list_by_notification.metadata['url']
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
            deserialized = self._deserialize('RecipientUserCollection', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_by_notification.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/notifications/{notificationName}/recipientUsers'}

    def check_entity_exists(
            self, resource_group_name, service_name, notification_name, user_id, custom_headers=None, raw=False, **operation_config):
        """Determine if the Notification Recipient User is subscribed to the
        notification.

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
        :param user_id: User identifier. Must be unique in the current API
         Management service instance.
        :type user_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: bool or ClientRawResponse if raw=true
        :rtype: bool or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.apimanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.check_entity_exists.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'serviceName': self._serialize.url("service_name", service_name, 'str', max_length=50, min_length=1, pattern=r'^[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'),
            'notificationName': self._serialize.url("notification_name", notification_name, 'str'),
            'userId': self._serialize.url("user_id", user_id, 'str', max_length=80, min_length=1, pattern=r'^[^*#&+:<>?]+$'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        request = self._client.head(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [204, 404]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = (response.status_code == 204)
        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response
        return deserialized
    check_entity_exists.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/notifications/{notificationName}/recipientUsers/{userId}'}

    def create_or_update(
            self, resource_group_name, service_name, notification_name, user_id, custom_headers=None, raw=False, **operation_config):
        """Adds the API Management User to the list of Recipients for the
        Notification.

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
        :param user_id: User identifier. Must be unique in the current API
         Management service instance.
        :type user_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: RecipientUserContract or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.apimanagement.models.RecipientUserContract or
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
            'userId': self._serialize.url("user_id", user_id, 'str', max_length=80, min_length=1, pattern=r'^[^*#&+:<>?]+$'),
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
        request = self._client.put(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('RecipientUserContract', response)
        if response.status_code == 201:
            deserialized = self._deserialize('RecipientUserContract', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/notifications/{notificationName}/recipientUsers/{userId}'}

    def delete(
            self, resource_group_name, service_name, notification_name, user_id, custom_headers=None, raw=False, **operation_config):
        """Removes the API Management user from the list of Notification.

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
        :param user_id: User identifier. Must be unique in the current API
         Management service instance.
        :type user_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.apimanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'serviceName': self._serialize.url("service_name", service_name, 'str', max_length=50, min_length=1, pattern=r'^[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$'),
            'notificationName': self._serialize.url("notification_name", notification_name, 'str'),
            'userId': self._serialize.url("user_id", user_id, 'str', max_length=80, min_length=1, pattern=r'^[^*#&+:<>?]+$'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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

        if response.status_code not in [200, 204]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiManagement/service/{serviceName}/notifications/{notificationName}/recipientUsers/{userId}'}
