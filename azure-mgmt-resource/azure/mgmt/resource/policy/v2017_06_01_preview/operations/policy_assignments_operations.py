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
import warnings
from msrest.pipeline import ClientRawResponse

from .. import models


class PolicyAssignmentsOperations(object):
    """PolicyAssignmentsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: The API version to use for the operation. Constant value: "2017-06-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-06-01-preview"

        self.config = config

    def delete(
            self, scope, policy_assignment_name, custom_headers=None, raw=False, **operation_config):
        """Deletes a policy assignment.

        :param scope: The scope of the policy assignment.
        :type scope: str
        :param policy_assignment_name: The name of the policy assignment to
         delete.
        :type policy_assignment_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PolicyAssignment or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'policyAssignmentName': self._serialize.url("policy_assignment_name", policy_assignment_name, 'str')
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
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PolicyAssignment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    delete.metadata = {'url': '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'}

    def create(
            self, scope, policy_assignment_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Creates a policy assignment.

        Policy assignments are inherited by child resources. For example, when
        you apply a policy to a resource group that policy is assigned to all
        resources in the group.

        :param scope: The scope of the policy assignment.
        :type scope: str
        :param policy_assignment_name: The name of the policy assignment.
        :type policy_assignment_name: str
        :param parameters: Parameters for the policy assignment.
        :type parameters:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PolicyAssignment or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'policyAssignmentName': self._serialize.url("policy_assignment_name", policy_assignment_name, 'str')
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
        body_content = self._serialize.body(parameters, 'PolicyAssignment')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 201:
            deserialized = self._deserialize('PolicyAssignment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create.metadata = {'url': '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'}

    def get(
            self, scope, policy_assignment_name, custom_headers=None, raw=False, **operation_config):
        """Gets a policy assignment.

        :param scope: The scope of the policy assignment.
        :type scope: str
        :param policy_assignment_name: The name of the policy assignment to
         get.
        :type policy_assignment_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PolicyAssignment or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'policyAssignmentName': self._serialize.url("policy_assignment_name", policy_assignment_name, 'str')
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
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PolicyAssignment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'}

    def list_for_resource_group(
            self, resource_group_name, filter=None, custom_headers=None, raw=False, **operation_config):
        """Gets policy assignments for the resource group.

        :param resource_group_name: The name of the resource group that
         contains policy assignments.
        :type resource_group_name: str
        :param filter: The filter to apply on the operation.
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PolicyAssignment
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignmentPaged[~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_for_resource_group.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str', skip_quote=True)
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
        deserialized = models.PolicyAssignmentPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.PolicyAssignmentPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_for_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/policyAssignments'}

    def list_for_resource(
            self, resource_group_name, resource_provider_namespace, parent_resource_path, resource_type, resource_name, filter=None, custom_headers=None, raw=False, **operation_config):
        """Gets policy assignments for a resource.

        .. warning::
           This method is deprecated

        :param resource_group_name: The name of the resource group containing
         the resource. The name is case insensitive.
        :type resource_group_name: str
        :param resource_provider_namespace: The namespace of the resource
         provider.
        :type resource_provider_namespace: str
        :param parent_resource_path: The parent resource path.
        :type parent_resource_path: str
        :param resource_type: The resource type.
        :type resource_type: str
        :param resource_name: The name of the resource with policy
         assignments.
        :type resource_name: str
        :param filter: The filter to apply on the operation.
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PolicyAssignment
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignmentPaged[~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
        warnings.warn("Method list_for_resource is deprecated", DeprecationWarning)
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_for_resource.metadata['url']
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
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
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
        deserialized = models.PolicyAssignmentPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.PolicyAssignmentPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_for_resource.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}/providers/Microsoft.Authorization/policyAssignments'}

    def list(
            self, filter=None, custom_headers=None, raw=False, **operation_config):
        """Gets all the policy assignments for a subscription.

        :param filter: The filter to apply on the operation.
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of PolicyAssignment
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignmentPaged[~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
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
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
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
        deserialized = models.PolicyAssignmentPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.PolicyAssignmentPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments'}

    def delete_by_id(
            self, policy_assignment_id, custom_headers=None, raw=False, **operation_config):
        """Deletes a policy assignment by ID.

        When providing a scope for the assigment, use
        '/subscriptions/{subscription-id}/' for subscriptions,
        '/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}'
        for resource groups, and
        '/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}'
        for resources.

        :param policy_assignment_id: The ID of the policy assignment to
         delete. Use the format
         '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policy-assignment-name}'.
        :type policy_assignment_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PolicyAssignment or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete_by_id.metadata['url']
        path_format_arguments = {
            'policyAssignmentId': self._serialize.url("policy_assignment_id", policy_assignment_id, 'str', skip_quote=True)
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

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PolicyAssignment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    delete_by_id.metadata = {'url': '/{policyAssignmentId}'}

    def create_by_id(
            self, policy_assignment_id, parameters, custom_headers=None, raw=False, **operation_config):
        """Creates a policy assignment by ID.

        Policy assignments are inherited by child resources. For example, when
        you apply a policy to a resource group that policy is assigned to all
        resources in the group. When providing a scope for the assigment, use
        '/subscriptions/{subscription-id}/' for subscriptions,
        '/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}'
        for resource groups, and
        '/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}'
        for resources.

        :param policy_assignment_id: The ID of the policy assignment to
         create. Use the format
         '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policy-assignment-name}'.
        :type policy_assignment_id: str
        :param parameters: Parameters for policy assignment.
        :type parameters:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PolicyAssignment or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create_by_id.metadata['url']
        path_format_arguments = {
            'policyAssignmentId': self._serialize.url("policy_assignment_id", policy_assignment_id, 'str', skip_quote=True)
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
        body_content = self._serialize.body(parameters, 'PolicyAssignment')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 201:
            deserialized = self._deserialize('PolicyAssignment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_by_id.metadata = {'url': '/{policyAssignmentId}'}

    def get_by_id(
            self, policy_assignment_id, custom_headers=None, raw=False, **operation_config):
        """Gets a policy assignment by ID.

        When providing a scope for the assigment, use
        '/subscriptions/{subscription-id}/' for subscriptions,
        '/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}'
        for resource groups, and
        '/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/{resource-provider-namespace}/{resource-type}/{resource-name}'
        for resources.

        :param policy_assignment_id: The ID of the policy assignment to get.
         Use the format
         '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policy-assignment-name}'.
        :type policy_assignment_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PolicyAssignment or ClientRawResponse if raw=true
        :rtype:
         ~azure.mgmt.resource.policy.v2017_06_01_preview.models.PolicyAssignment
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.resource.policy.v2017_06_01_preview.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get_by_id.metadata['url']
        path_format_arguments = {
            'policyAssignmentId': self._serialize.url("policy_assignment_id", policy_assignment_id, 'str', skip_quote=True)
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
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('PolicyAssignment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_by_id.metadata = {'url': '/{policyAssignmentId}'}
