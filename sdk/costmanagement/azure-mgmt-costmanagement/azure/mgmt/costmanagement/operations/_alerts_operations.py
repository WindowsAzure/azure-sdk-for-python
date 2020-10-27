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


class AlertsOperations(object):
    """AlertsOperations operations.

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
            self, scope, custom_headers=None, raw=False, **operation_config):
        """Lists the alerts for scope defined.

        :param scope: The scope associated with alerts operations. This
         includes '/subscriptions/{subscriptionId}/' for subscription scope,
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
         for resourceGroup scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for
         Billing Account scope and
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/departments/{departmentId}'
         for Department scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/enrollmentAccounts/{enrollmentAccountId}'
         for EnrollmentAccount scope,
         '/providers/Microsoft.Management/managementGroups/{managementGroupId}
         for Management Group scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}'
         for billingProfile scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: AlertsResult or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.AlertsResult or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True)
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
            deserialized = self._deserialize('AlertsResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/alerts'}

    def get(
            self, scope, alert_id, custom_headers=None, raw=False, **operation_config):
        """Gets the alert for the scope by alert ID.

        :param scope: The scope associated with alerts operations. This
         includes '/subscriptions/{subscriptionId}/' for subscription scope,
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
         for resourceGroup scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for
         Billing Account scope and
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/departments/{departmentId}'
         for Department scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/enrollmentAccounts/{enrollmentAccountId}'
         for EnrollmentAccount scope,
         '/providers/Microsoft.Management/managementGroups/{managementGroupId}
         for Management Group scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}'
         for billingProfile scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param alert_id: Alert ID
        :type alert_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Alert or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.Alert or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'alertId': self._serialize.url("alert_id", alert_id, 'str', skip_quote=True)
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
            deserialized = self._deserialize('Alert', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/alerts/{alertId}'}

    def dismiss(
            self, scope, alert_id, parameters, custom_headers=None, raw=False, **operation_config):
        """Dismisses the specified alert.

        :param scope: The scope associated with alerts operations. This
         includes '/subscriptions/{subscriptionId}/' for subscription scope,
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}'
         for resourceGroup scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}' for
         Billing Account scope and
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/departments/{departmentId}'
         for Department scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/enrollmentAccounts/{enrollmentAccountId}'
         for EnrollmentAccount scope,
         '/providers/Microsoft.Management/managementGroups/{managementGroupId}
         for Management Group scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}'
         for billingProfile scope,
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         '/providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param alert_id: Alert ID
        :type alert_id: str
        :param parameters: Parameters supplied to the Dismiss Alert operation.
        :type parameters:
         ~azure.mgmt.costmanagement.models.DismissAlertPayload
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Alert or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.Alert or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.dismiss.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'alertId': self._serialize.url("alert_id", alert_id, 'str', skip_quote=True)
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
        body_content = self._serialize.body(parameters, 'DismissAlertPayload')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('Alert', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    dismiss.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/alerts/{alertId}'}

    def list_external(
            self, external_cloud_provider_type, external_cloud_provider_id, custom_headers=None, raw=False, **operation_config):
        """Lists the Alerts for external cloud provider type defined.

        :param external_cloud_provider_type: The external cloud provider type
         associated with dimension/query operations. This includes
         'externalSubscriptions' for linked account and
         'externalBillingAccounts' for consolidated account. Possible values
         include: 'externalSubscriptions', 'externalBillingAccounts'
        :type external_cloud_provider_type: str or
         ~azure.mgmt.costmanagement.models.ExternalCloudProviderType
        :param external_cloud_provider_id: This can be
         '{externalSubscriptionId}' for linked account or
         '{externalBillingAccountId}' for consolidated account used with
         dimension/query operations.
        :type external_cloud_provider_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: AlertsResult or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.AlertsResult or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list_external.metadata['url']
        path_format_arguments = {
            'externalCloudProviderType': self._serialize.url("external_cloud_provider_type", external_cloud_provider_type, 'str'),
            'externalCloudProviderId': self._serialize.url("external_cloud_provider_id", external_cloud_provider_id, 'str')
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
            deserialized = self._deserialize('AlertsResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_external.metadata = {'url': '/providers/Microsoft.CostManagement/{externalCloudProviderType}/{externalCloudProviderId}/alerts'}
