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


class MarketplacesByEnrollmentAccountsOperations(object):
    """MarketplacesByEnrollmentAccountsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. The current version is 2018-06-30. Constant value: "2018-06-30".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-06-30"

        self.config = config

    def list(
            self, enrollment_account_id, filter=None, top=None, skiptoken=None, custom_headers=None, raw=False, **operation_config):
        """Lists the marketplaces for a scope by enrollmentAccountId and current
        billing period. Marketplaces are available via this API only for May 1,
        2014 or later.

        :param enrollment_account_id: EnrollmentAccount ID
        :type enrollment_account_id: str
        :param filter: May be used to filter marketplaces by
         properties/usageEnd (Utc time), properties/usageStart (Utc time),
         properties/resourceGroup, properties/instanceName or
         properties/instanceId. The filter supports 'eq', 'lt', 'gt', 'le',
         'ge', and 'and'. It does not currently support 'ne', 'or', or 'not'.
        :type filter: str
        :param top: May be used to limit the number of results to the most
         recent N marketplaces.
        :type top: int
        :param skiptoken: Skiptoken is only used if a previous operation
         returned a partial result. If a previous response contains a nextLink
         element, the value of the nextLink element will include a skiptoken
         parameter that specifies a starting point to use for subsequent calls.
        :type skiptoken: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Marketplace
        :rtype:
         ~azure.mgmt.consumption.models.MarketplacePaged[~azure.mgmt.consumption.models.Marketplace]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.consumption.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'enrollmentAccountId': self._serialize.url("enrollment_account_id", enrollment_account_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', maximum=1000, minimum=1)
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

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
            response = self._client.send(
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.MarketplacePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.MarketplacePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/providers/Microsoft.Billing/enrollmentAccounts/{enrollmentAccountId}/providers/Microsoft.Consumption/marketplaces'}

    def list_by_billing_period(
            self, enrollment_account_id, billing_period_name, filter=None, top=None, skiptoken=None, custom_headers=None, raw=False, **operation_config):
        """Lists the marketplaces for a scope by billing period and
        enrollmentAccountId. Marketplaces are available via this API only for
        May 1, 2014 or later.

        :param enrollment_account_id: EnrollmentAccount ID
        :type enrollment_account_id: str
        :param billing_period_name: Billing Period Name.
        :type billing_period_name: str
        :param filter: May be used to filter marketplaces by
         properties/usageEnd (Utc time), properties/usageStart (Utc time),
         properties/resourceGroup, properties/instanceName or
         properties/instanceId. The filter supports 'eq', 'lt', 'gt', 'le',
         'ge', and 'and'. It does not currently support 'ne', 'or', or 'not'.
        :type filter: str
        :param top: May be used to limit the number of results to the most
         recent N marketplaces.
        :type top: int
        :param skiptoken: Skiptoken is only used if a previous operation
         returned a partial result. If a previous response contains a nextLink
         element, the value of the nextLink element will include a skiptoken
         parameter that specifies a starting point to use for subsequent calls.
        :type skiptoken: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Marketplace
        :rtype:
         ~azure.mgmt.consumption.models.MarketplacePaged[~azure.mgmt.consumption.models.Marketplace]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.consumption.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_billing_period.metadata['url']
                path_format_arguments = {
                    'enrollmentAccountId': self._serialize.url("enrollment_account_id", enrollment_account_id, 'str'),
                    'billingPeriodName': self._serialize.url("billing_period_name", billing_period_name, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', maximum=1000, minimum=1)
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

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
            response = self._client.send(
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.MarketplacePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.MarketplacePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_billing_period.metadata = {'url': '/providers/Microsoft.Billing/enrollmentAccounts/{enrollmentAccountId}/providers/Microsoft.Billing/billingPeriods/{billingPeriodName}/providers/Microsoft.Consumption/marketplaces'}
