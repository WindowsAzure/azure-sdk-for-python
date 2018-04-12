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


class UsageDetailsOperations(object):
    """UsageDetailsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. The current version is 2018-03-31. Constant value: "2018-03-31".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-03-31"

        self.config = config

    def list(
            self, expand=None, filter=None, skiptoken=None, top=None, query_options=None, custom_headers=None, raw=False, **operation_config):
        """Lists the usage details for a scope by current billing period. Usage
        details are available via this API only for May 1, 2014 or later.

        :param expand: May be used to expand the
         properties/additionalProperties or properties/meterDetails within a
         list of usage details. By default, these fields are not included when
         listing usage details.
        :type expand: str
        :param filter: May be used to filter usageDetails by
         properties/usageEnd (Utc time), properties/usageStart (Utc time),
         properties/resourceGroup, properties/instanceName,
         properties/instanceId or tags. The filter supports 'eq', 'lt', 'gt',
         'le', 'ge', and 'and'. It does not currently support 'ne', 'or', or
         'not'. Tag filter is a key value pair string where key and value is
         separated by a colon (:).
        :type filter: str
        :param skiptoken: Skiptoken is only used if a previous operation
         returned a partial result. If a previous response contains a nextLink
         element, the value of the nextLink element will include a skiptoken
         parameter that specifies a starting point to use for subsequent calls.
        :type skiptoken: str
        :param top: May be used to limit the number of results to the most
         recent N usageDetails.
        :type top: int
        :param query_options: Additional parameters for the operation
        :type query_options: ~azure.mgmt.consumption.models.QueryOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of UsageDetail
        :rtype:
         ~azure.mgmt.consumption.models.UsageDetailPaged[~azure.mgmt.consumption.models.UsageDetail]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.consumption.models.ErrorResponseException>`
        """
        apply = None
        if query_options is not None:
            apply = query_options.apply

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if expand is not None:
                    query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', maximum=1000, minimum=1)
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if apply is not None:
                    query_parameters['$apply'] = self._serialize.query("apply", apply, 'str')

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
        deserialized = models.UsageDetailPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.UsageDetailPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Consumption/usageDetails'}

    def list_by_billing_period(
            self, billing_period_name, expand=None, filter=None, skiptoken=None, top=None, query_options=None, custom_headers=None, raw=False, **operation_config):
        """Lists the usage details for a scope by billing period. Usage details
        are available via this API only for May 1, 2014 or later.

        :param billing_period_name: Billing Period Name.
        :type billing_period_name: str
        :param expand: May be used to expand the
         properties/additionalProperties or properties/meterDetails within a
         list of usage details. By default, these fields are not included when
         listing usage details.
        :type expand: str
        :param filter: May be used to filter usageDetails by
         properties/usageEnd (Utc time), properties/usageStart (Utc time),
         properties/resourceGroup, properties/instanceName or
         properties/instanceId. The filter supports 'eq', 'lt', 'gt', 'le',
         'ge', and 'and'. It does not currently support 'ne', 'or', or 'not'.
         Tag filter is a key value pair string where key and value is separated
         by a colon (:).
        :type filter: str
        :param skiptoken: Skiptoken is only used if a previous operation
         returned a partial result. If a previous response contains a nextLink
         element, the value of the nextLink element will include a skiptoken
         parameter that specifies a starting point to use for subsequent calls.
        :type skiptoken: str
        :param top: May be used to limit the number of results to the most
         recent N usageDetails.
        :type top: int
        :param query_options: Additional parameters for the operation
        :type query_options: ~azure.mgmt.consumption.models.QueryOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of UsageDetail
        :rtype:
         ~azure.mgmt.consumption.models.UsageDetailPaged[~azure.mgmt.consumption.models.UsageDetail]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.consumption.models.ErrorResponseException>`
        """
        apply = None
        if query_options is not None:
            apply = query_options.apply

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_by_billing_period.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'billingPeriodName': self._serialize.url("billing_period_name", billing_period_name, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if expand is not None:
                    query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', maximum=1000, minimum=1)
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if apply is not None:
                    query_parameters['$apply'] = self._serialize.query("apply", apply, 'str')

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
        deserialized = models.UsageDetailPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.UsageDetailPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_by_billing_period.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Billing/billingPeriods/{billingPeriodName}/providers/Microsoft.Consumption/usageDetails'}
