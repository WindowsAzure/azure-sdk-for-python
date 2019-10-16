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


class ExportsOperations(object):
    """ExportsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. The current version is 2018-05-31. Constant value: "2019-10-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-10-01"

        self.config = config

    def list(
            self, scope, custom_headers=None, raw=False, **operation_config):
        """The operation to list all exports at the given scope.

        :param scope: The scope associated with query and export operations.
         This includes '/subscriptions/{subscriptionId}/' for subscription
         scope,
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
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ExportListResult or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.ExportListResult or
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
            deserialized = self._deserialize('ExportListResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/exports'}

    def get(
            self, scope, export_name, custom_headers=None, raw=False, **operation_config):
        """The operation to get the export for the defined scope by export name.

        :param scope: The scope associated with query and export operations.
         This includes '/subscriptions/{subscriptionId}/' for subscription
         scope,
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
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param export_name: Export Name.
        :type export_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Export or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.Export or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'exportName': self._serialize.url("export_name", export_name, 'str')
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
            deserialized = self._deserialize('Export', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/exports/{exportName}'}

    def create_or_update(
            self, scope, export_name, parameters, custom_headers=None, raw=False, **operation_config):
        """The operation to create or update a export. Update operation requires
        latest eTag to be set in the request. You may obtain the latest eTag by
        performing a get operation. Create operation does not require eTag.

        :param scope: The scope associated with query and export operations.
         This includes '/subscriptions/{subscriptionId}/' for subscription
         scope,
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
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param export_name: Export Name.
        :type export_name: str
        :param parameters: Parameters supplied to the CreateOrUpdate Export
         operation.
        :type parameters: ~azure.mgmt.costmanagement.models.Export
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Export or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.Export or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'exportName': self._serialize.url("export_name", export_name, 'str')
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
        body_content = self._serialize.body(parameters, 'Export')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Export', response)
        if response.status_code == 201:
            deserialized = self._deserialize('Export', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/exports/{exportName}'}

    def delete(
            self, scope, export_name, custom_headers=None, raw=False, **operation_config):
        """The operation to delete a export.

        :param scope: The scope associated with query and export operations.
         This includes '/subscriptions/{subscriptionId}/' for subscription
         scope,
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
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param export_name: Export Name.
        :type export_name: str
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
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'exportName': self._serialize.url("export_name", export_name, 'str')
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

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/exports/{exportName}'}

    def execute(
            self, scope, export_name, custom_headers=None, raw=False, **operation_config):
        """The operation to execute a export.

        :param scope: The scope associated with query and export operations.
         This includes '/subscriptions/{subscriptionId}/' for subscription
         scope,
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
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param export_name: Export Name.
        :type export_name: str
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
        url = self.execute.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'exportName': self._serialize.url("export_name", export_name, 'str')
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
        request = self._client.post(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    execute.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/exports/{exportName}/run'}

    def get_execution_history(
            self, scope, export_name, custom_headers=None, raw=False, **operation_config):
        """The operation to get the execution history of an export for the defined
        scope by export name.

        :param scope: The scope associated with query and export operations.
         This includes '/subscriptions/{subscriptionId}/' for subscription
         scope,
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
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/billingProfiles/{billingProfileId}/invoiceSections/{invoiceSectionId}'
         for invoiceSection scope, and
         'providers/Microsoft.Billing/billingAccounts/{billingAccountId}/customers/{customerId}'
         specific for partners.
        :type scope: str
        :param export_name: Export Name.
        :type export_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ExportExecutionListResult or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.costmanagement.models.ExportExecutionListResult or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.costmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get_execution_history.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'exportName': self._serialize.url("export_name", export_name, 'str')
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
            deserialized = self._deserialize('ExportExecutionListResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_execution_history.metadata = {'url': '/{scope}/providers/Microsoft.CostManagement/exports/{exportName}/runHistory'}
