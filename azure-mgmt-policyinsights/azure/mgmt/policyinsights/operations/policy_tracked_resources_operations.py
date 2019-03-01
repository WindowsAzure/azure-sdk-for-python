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


class PolicyTrackedResourcesOperations(object):
    """PolicyTrackedResourcesOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar management_groups_namespace: The namespace for Microsoft Management RP; only "Microsoft.Management" is allowed. Constant value: "Microsoft.Management".
    :ivar policy_tracked_resources_resource: The name of the virtual resource under PolicyTrackedResources resource type; only "default" is allowed. Constant value: "default".
    :ivar api_version: Client Api Version. Constant value: "2018-07-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.management_groups_namespace = "Microsoft.Management"
        self.policy_tracked_resources_resource = "default"
        self.api_version = "2018-07-01-preview"

        self.config = config

    def list_query_results_for_management_group(
            self, management_group_name, query_options=None, custom_headers=None, raw=False, **operation_config):
        """Queries policy tracked resources under the management group.

        :param management_group_name: Management group name.
        :type management_group_name: str
        :param query_options: Additional parameters for the operation
        :type query_options: ~azure.mgmt.policyinsights.models.QueryOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PolicyTrackedResource
        :rtype:
         ~azure.mgmt.policyinsights.models.PolicyTrackedResourcePaged[~azure.mgmt.policyinsights.models.PolicyTrackedResource]
        :raises:
         :class:`QueryFailureException<azure.mgmt.policyinsights.models.QueryFailureException>`
        """
        top = None
        if query_options is not None:
            top = query_options.top
        filter = None
        if query_options is not None:
            filter = query_options.filter

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_query_results_for_management_group.metadata['url']
                path_format_arguments = {
                    'managementGroupsNamespace': self._serialize.url("self.management_groups_namespace", self.management_groups_namespace, 'str'),
                    'managementGroupName': self._serialize.url("management_group_name", management_group_name, 'str'),
                    'policyTrackedResourcesResource': self._serialize.url("self.policy_tracked_resources_resource", self.policy_tracked_resources_resource, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', minimum=0)
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

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
            request = self._client.post(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.QueryFailureException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.PolicyTrackedResourcePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.PolicyTrackedResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_query_results_for_management_group.metadata = {'url': '/providers/{managementGroupsNamespace}/managementGroups/{managementGroupName}/providers/Microsoft.PolicyInsights/policyTrackedResources/{policyTrackedResourcesResource}/queryResults'}

    def list_query_results_for_subscription(
            self, subscription_id, query_options=None, custom_headers=None, raw=False, **operation_config):
        """Queries policy tracked resources under the subscription.

        :param subscription_id: Microsoft Azure subscription ID.
        :type subscription_id: str
        :param query_options: Additional parameters for the operation
        :type query_options: ~azure.mgmt.policyinsights.models.QueryOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PolicyTrackedResource
        :rtype:
         ~azure.mgmt.policyinsights.models.PolicyTrackedResourcePaged[~azure.mgmt.policyinsights.models.PolicyTrackedResource]
        :raises:
         :class:`QueryFailureException<azure.mgmt.policyinsights.models.QueryFailureException>`
        """
        top = None
        if query_options is not None:
            top = query_options.top
        filter = None
        if query_options is not None:
            filter = query_options.filter

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_query_results_for_subscription.metadata['url']
                path_format_arguments = {
                    'policyTrackedResourcesResource': self._serialize.url("self.policy_tracked_resources_resource", self.policy_tracked_resources_resource, 'str'),
                    'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', minimum=0)
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

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
            request = self._client.post(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.QueryFailureException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.PolicyTrackedResourcePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.PolicyTrackedResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_query_results_for_subscription.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyTrackedResources/{policyTrackedResourcesResource}/queryResults'}

    def list_query_results_for_resource_group(
            self, resource_group_name, subscription_id, query_options=None, custom_headers=None, raw=False, **operation_config):
        """Queries policy tracked resources under the resource group.

        :param resource_group_name: Resource group name.
        :type resource_group_name: str
        :param subscription_id: Microsoft Azure subscription ID.
        :type subscription_id: str
        :param query_options: Additional parameters for the operation
        :type query_options: ~azure.mgmt.policyinsights.models.QueryOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PolicyTrackedResource
        :rtype:
         ~azure.mgmt.policyinsights.models.PolicyTrackedResourcePaged[~azure.mgmt.policyinsights.models.PolicyTrackedResource]
        :raises:
         :class:`QueryFailureException<azure.mgmt.policyinsights.models.QueryFailureException>`
        """
        top = None
        if query_options is not None:
            top = query_options.top
        filter = None
        if query_options is not None:
            filter = query_options.filter

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_query_results_for_resource_group.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'policyTrackedResourcesResource': self._serialize.url("self.policy_tracked_resources_resource", self.policy_tracked_resources_resource, 'str'),
                    'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', minimum=0)
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

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
            request = self._client.post(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.QueryFailureException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.PolicyTrackedResourcePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.PolicyTrackedResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_query_results_for_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.PolicyInsights/policyTrackedResources/{policyTrackedResourcesResource}/queryResults'}

    def list_query_results_for_resource(
            self, resource_id, query_options=None, custom_headers=None, raw=False, **operation_config):
        """Queries policy tracked resources under the resource.

        :param resource_id: Resource ID.
        :type resource_id: str
        :param query_options: Additional parameters for the operation
        :type query_options: ~azure.mgmt.policyinsights.models.QueryOptions
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PolicyTrackedResource
        :rtype:
         ~azure.mgmt.policyinsights.models.PolicyTrackedResourcePaged[~azure.mgmt.policyinsights.models.PolicyTrackedResource]
        :raises:
         :class:`QueryFailureException<azure.mgmt.policyinsights.models.QueryFailureException>`
        """
        top = None
        if query_options is not None:
            top = query_options.top
        filter = None
        if query_options is not None:
            filter = query_options.filter

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_query_results_for_resource.metadata['url']
                path_format_arguments = {
                    'resourceId': self._serialize.url("resource_id", resource_id, 'str', skip_quote=True),
                    'policyTrackedResourcesResource': self._serialize.url("self.policy_tracked_resources_resource", self.policy_tracked_resources_resource, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int', minimum=0)
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

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
            request = self._client.post(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.QueryFailureException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.PolicyTrackedResourcePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.PolicyTrackedResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_query_results_for_resource.metadata = {'url': '/{resourceId}/providers/Microsoft.PolicyInsights/policyTrackedResources/{policyTrackedResourcesResource}/queryResults'}
