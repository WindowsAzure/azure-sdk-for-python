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


class ViewsOperations(object):
    """ViewsOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. The current version is 2020-06-01. Constant value: "2020-06-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2020-06-01"

        self.config = config

    def list(
            self, custom_headers=None, raw=False, **operation_config):
        """Lists all views by tenant and object.

        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of View
        :rtype:
         ~azure.mgmt.costmanagement.models.ViewPaged[~azure.mgmt.costmanagement.models.View]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list.metadata['url']

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
        deserialized = models.ViewPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list.metadata = {'url': '/providers/Microsoft.CostManagement/views'}

    def list_by_scope(
            self, scope, custom_headers=None, raw=False, **operation_config):
        """Lists all views at the given scope.

        :param scope: The scope associated with view operations. This includes
         'subscriptions/{subscriptionId}' for subscription scope,
         'subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
         for resourceGroup scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for
         Billing Account scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/departments/{departmentId}'
         for Department scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/enrollmentAccounts/{enrollmentAccountId}'
         for EnrollmentAccount scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}'
         for BillingProfile scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/invoiceSections/{invoiceSectionId}'
         for InvoiceSection scope,
         'providers/Microsoft.Management/managementGroups/{managementGroupId}'
         for Management Group scope,
         'providers/Microsoft.CostManagement/externalBillingAccounts/{externalBillingAccountName}'
         for External Billing Account scope and
         'providers/Microsoft.CostManagement/externalSubscriptions/{externalSubscriptionName}'
         for External Subscription scope.
        :type scope: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of View
        :rtype:
         ~azure.mgmt.costmanagement.models.ViewPaged[~azure.mgmt.costmanagement.models.View]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_scope.metadata['url']
                path_format_arguments = {
                    'scope': self._serialize.url("scope", scope, 'str')
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
        deserialized = models.ViewPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_by_scope.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/views'}

    def get(
            self, view_name, custom_headers=None, raw=False, **operation_config):
        """Gets the view by view name.

        :param view_name: View name
        :type view_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: View or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.View or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'viewName': self._serialize.url("view_name", view_name, 'str')
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
            deserialized = self._deserialize('View', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/providers/Microsoft.CostManagement/views/{viewName}'}

    def create_or_update(
            self, view_name, parameters, custom_headers=None, raw=False, **operation_config):
        """The operation to create or update a view. Update operation requires
        latest eTag to be set in the request. You may obtain the latest eTag by
        performing a get operation. Create operation does not require eTag.

        :param view_name: View name
        :type view_name: str
        :param parameters: Parameters supplied to the CreateOrUpdate View
         operation.
        :type parameters: ~azure.mgmt.costmanagement.models.View
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: View or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.View or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'viewName': self._serialize.url("view_name", view_name, 'str')
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
        body_content = self._serialize.body(parameters, 'View')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('View', response)
        if response.status_code == 201:
            deserialized = self._deserialize('View', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/providers/Microsoft.CostManagement/views/{viewName}'}

    def delete(
            self, view_name, custom_headers=None, raw=False, **operation_config):
        """The operation to delete a view.

        :param view_name: View name
        :type view_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'viewName': self._serialize.url("view_name", view_name, 'str')
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
    delete.metadata = {'url': '/providers/Microsoft.CostManagement/views/{viewName}'}

    def get_by_scope(
            self, scope, view_name, custom_headers=None, raw=False, **operation_config):
        """Gets the view for the defined scope by view name.

        :param scope: The scope associated with view operations. This includes
         'subscriptions/{subscriptionId}' for subscription scope,
         'subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
         for resourceGroup scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for
         Billing Account scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/departments/{departmentId}'
         for Department scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/enrollmentAccounts/{enrollmentAccountId}'
         for EnrollmentAccount scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}'
         for BillingProfile scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/invoiceSections/{invoiceSectionId}'
         for InvoiceSection scope,
         'providers/Microsoft.Management/managementGroups/{managementGroupId}'
         for Management Group scope,
         'providers/Microsoft.CostManagement/externalBillingAccounts/{externalBillingAccountName}'
         for External Billing Account scope and
         'providers/Microsoft.CostManagement/externalSubscriptions/{externalSubscriptionName}'
         for External Subscription scope.
        :type scope: str
        :param view_name: View name
        :type view_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: View or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.View or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get_by_scope.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str'),
            'viewName': self._serialize.url("view_name", view_name, 'str')
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
            deserialized = self._deserialize('View', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_by_scope.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/views/{viewName}'}

    def create_or_update_by_scope(
            self, scope, view_name, parameters, custom_headers=None, raw=False, **operation_config):
        """The operation to create or update a view. Update operation requires
        latest eTag to be set in the request. You may obtain the latest eTag by
        performing a get operation. Create operation does not require eTag.

        :param scope: The scope associated with view operations. This includes
         'subscriptions/{subscriptionId}' for subscription scope,
         'subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
         for resourceGroup scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for
         Billing Account scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/departments/{departmentId}'
         for Department scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/enrollmentAccounts/{enrollmentAccountId}'
         for EnrollmentAccount scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}'
         for BillingProfile scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/invoiceSections/{invoiceSectionId}'
         for InvoiceSection scope,
         'providers/Microsoft.Management/managementGroups/{managementGroupId}'
         for Management Group scope,
         'providers/Microsoft.CostManagement/externalBillingAccounts/{externalBillingAccountName}'
         for External Billing Account scope and
         'providers/Microsoft.CostManagement/externalSubscriptions/{externalSubscriptionName}'
         for External Subscription scope.
        :type scope: str
        :param view_name: View name
        :type view_name: str
        :param parameters: Parameters supplied to the CreateOrUpdate View
         operation.
        :type parameters: ~azure.mgmt.costmanagement.models.View
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: View or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.View or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create_or_update_by_scope.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str'),
            'viewName': self._serialize.url("view_name", view_name, 'str')
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
        body_content = self._serialize.body(parameters, 'View')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('View', response)
        if response.status_code == 201:
            deserialized = self._deserialize('View', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update_by_scope.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/views/{viewName}'}

    def delete_by_scope(
            self, scope, view_name, custom_headers=None, raw=False, **operation_config):
        """The operation to delete a view.

        :param scope: The scope associated with view operations. This includes
         'subscriptions/{subscriptionId}' for subscription scope,
         'subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
         for resourceGroup scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for
         Billing Account scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/departments/{departmentId}'
         for Department scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/enrollmentAccounts/{enrollmentAccountId}'
         for EnrollmentAccount scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}'
         for BillingProfile scope,
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/invoiceSections/{invoiceSectionId}'
         for InvoiceSection scope,
         'providers/Microsoft.Management/managementGroups/{managementGroupId}'
         for Management Group scope,
         'providers/Microsoft.CostManagement/externalBillingAccounts/{externalBillingAccountName}'
         for External Billing Account scope and
         'providers/Microsoft.CostManagement/externalSubscriptions/{externalSubscriptionName}'
         for External Subscription scope.
        :type scope: str
        :param view_name: View name
        :type view_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete_by_scope.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str'),
            'viewName': self._serialize.url("view_name", view_name, 'str')
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
    delete_by_scope.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/views/{viewName}'}
