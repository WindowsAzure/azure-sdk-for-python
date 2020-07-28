# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

from .. import models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class PolicyAssignmentsOperations(object):
    """PolicyAssignmentsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.resource.policy.v2019_01_01.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def delete(
        self,
        scope,  # type: str
        policy_assignment_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PolicyAssignment"
        """Deletes a policy assignment.

        This operation deletes a policy assignment, given its name and the scope it was created in. The
        scope of a policy assignment is the part of its ID preceding
        '/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'.

        :param scope: The scope of the policy assignment. Valid scopes are: management group (format:
         '/providers/Microsoft.Management/managementGroups/{managementGroup}'), subscription (format:
         '/subscriptions/{subscriptionId}'), resource group (format:
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}', or resource (format:
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/[{parentResourcePath}/]{resourceType}/{resourceName}'.
        :type scope: str
        :param policy_assignment_name: The name of the policy assignment to delete.
        :type policy_assignment_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PolicyAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignment or None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignment"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'policyAssignmentName': self._serialize.url("policy_assignment_name", policy_assignment_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('PolicyAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    delete.metadata = {'url': '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'}  # type: ignore

    def create(
        self,
        scope,  # type: str
        policy_assignment_name,  # type: str
        parameters,  # type: "models.PolicyAssignment"
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PolicyAssignment"
        """Creates or updates a policy assignment.

        This operation creates or updates a policy assignment with the given scope and name. Policy
        assignments apply to all resources contained within their scope. For example, when you assign a
        policy at resource group scope, that policy applies to all resources in the group.

        :param scope: The scope of the policy assignment. Valid scopes are: management group (format:
         '/providers/Microsoft.Management/managementGroups/{managementGroup}'), subscription (format:
         '/subscriptions/{subscriptionId}'), resource group (format:
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}', or resource (format:
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/[{parentResourcePath}/]{resourceType}/{resourceName}'.
        :type scope: str
        :param policy_assignment_name: The name of the policy assignment.
        :type policy_assignment_name: str
        :param parameters: Parameters for the policy assignment.
        :type parameters: ~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignment
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PolicyAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignment"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self.create.metadata['url']  # type: ignore
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'policyAssignmentName': self._serialize.url("policy_assignment_name", policy_assignment_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(parameters, 'PolicyAssignment')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('PolicyAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create.metadata = {'url': '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'}  # type: ignore

    def get(
        self,
        scope,  # type: str
        policy_assignment_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PolicyAssignment"
        """Retrieves a policy assignment.

        This operation retrieves a single policy assignment, given its name and the scope it was
        created at.

        :param scope: The scope of the policy assignment. Valid scopes are: management group (format:
         '/providers/Microsoft.Management/managementGroups/{managementGroup}'), subscription (format:
         '/subscriptions/{subscriptionId}'), resource group (format:
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}', or resource (format:
         '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/[{parentResourcePath}/]{resourceType}/{resourceName}'.
        :type scope: str
        :param policy_assignment_name: The name of the policy assignment to get.
        :type policy_assignment_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PolicyAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignment"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'policyAssignmentName': self._serialize.url("policy_assignment_name", policy_assignment_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('PolicyAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'}  # type: ignore

    def list_for_resource_group(
        self,
        resource_group_name,  # type: str
        filter=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.PolicyAssignmentListResult"]
        """Retrieves all policy assignments that apply to a resource group.

        This operation retrieves the list of all policy assignments associated with the given resource
    group in the given subscription that match the optional given $filter. Valid values for $filter
    are: 'atScope()' or 'policyDefinitionId eq '{value}''. If $filter is not provided, the
    unfiltered list includes all policy assignments associated with the resource group, including
    those that apply directly or apply from containing scopes, as well as any applied to resources
    contained within the resource group. If $filter=atScope() is provided, the returned list
    includes all policy assignments that apply to the resource group, which is everything in the
    unfiltered list except those applied to resources contained within the resource group. If
    $filter=policyDefinitionId eq '{value}' is provided, the returned list includes all policy
    assignments of the policy definition whose id is {value} that apply to the resource group.

        :param resource_group_name: The name of the resource group that contains policy assignments.
        :type resource_group_name: str
        :param filter: The filter to apply on the operation. Valid values for $filter are: 'atScope()'
     or 'policyDefinitionId eq '{value}''. If $filter is not provided, no filtering is performed.
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either PolicyAssignmentListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignmentListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignmentListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_for_resource_group.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str', skip_quote=True)
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('PolicyAssignmentListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_for_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Authorization/policyAssignments'}  # type: ignore

    def list_for_resource(
        self,
        resource_group_name,  # type: str
        resource_provider_namespace,  # type: str
        parent_resource_path,  # type: str
        resource_type,  # type: str
        resource_name,  # type: str
        filter=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.PolicyAssignmentListResult"]
        """Retrieves all policy assignments that apply to a resource.

        This operation retrieves the list of all policy assignments associated with the specified
    resource in the given resource group and subscription that match the optional given $filter.
    Valid values for $filter are: 'atScope()' or 'policyDefinitionId eq '{value}''. If $filter is
    not provided, the unfiltered list includes all policy assignments associated with the resource,
    including those that apply directly or from all containing scopes, as well as any applied to
    resources contained within the resource. If $filter=atScope() is provided, the returned list
    includes all policy assignments that apply to the resource, which is everything in the
    unfiltered list except those applied to resources contained within the resource. If
    $filter=policyDefinitionId eq '{value}' is provided, the returned list includes all policy
    assignments of the policy definition whose id is {value} that apply to the resource. Three
    parameters plus the resource name are used to identify a specific resource. If the resource is
    not part of a parent resource (the more common case), the parent resource path should not be
    provided (or provided as ''). For example a web app could be specified as
    ({resourceProviderNamespace} == 'Microsoft.Web', {parentResourcePath} == '', {resourceType} ==
    'sites', {resourceName} == 'MyWebApp'). If the resource is part of a parent resource, then all
    parameters should be provided. For example a virtual machine DNS name could be specified as
    ({resourceProviderNamespace} == 'Microsoft.Compute', {parentResourcePath} ==
    'virtualMachines/MyVirtualMachine', {resourceType} == 'domainNames', {resourceName} ==
    'MyComputerName'). A convenient alternative to providing the namespace and type name separately
    is to provide both in the {resourceType} parameter, format: ({resourceProviderNamespace} == '',
    {parentResourcePath} == '', {resourceType} == 'Microsoft.Web/sites', {resourceName} ==
    'MyWebApp').

        :param resource_group_name: The name of the resource group containing the resource.
        :type resource_group_name: str
        :param resource_provider_namespace: The namespace of the resource provider. For example, the
     namespace of a virtual machine is Microsoft.Compute (from Microsoft.Compute/virtualMachines).
        :type resource_provider_namespace: str
        :param parent_resource_path: The parent resource path. Use empty string if there is none.
        :type parent_resource_path: str
        :param resource_type: The resource type name. For example the type name of a web app is 'sites'
     (from Microsoft.Web/sites).
        :type resource_type: str
        :param resource_name: The name of the resource.
        :type resource_name: str
        :param filter: The filter to apply on the operation. Valid values for $filter are: 'atScope()'
     or 'policyDefinitionId eq '{value}''. If $filter is not provided, no filtering is performed.
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either PolicyAssignmentListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignmentListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignmentListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_for_resource.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'resourceProviderNamespace': self._serialize.url("resource_provider_namespace", resource_provider_namespace, 'str'),
                    'parentResourcePath': self._serialize.url("parent_resource_path", parent_resource_path, 'str', skip_quote=True),
                    'resourceType': self._serialize.url("resource_type", resource_type, 'str', skip_quote=True),
                    'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('PolicyAssignmentListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_for_resource.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{parentResourcePath}/{resourceType}/{resourceName}/providers/Microsoft.Authorization/policyAssignments'}  # type: ignore

    def list(
        self,
        filter=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.PolicyAssignmentListResult"]
        """Retrieves all policy assignments that apply to a subscription.

        This operation retrieves the list of all policy assignments associated with the given
    subscription that match the optional given $filter. Valid values for $filter are: 'atScope()'
    or 'policyDefinitionId eq '{value}''. If $filter is not provided, the unfiltered list includes
    all policy assignments associated with the subscription, including those that apply directly or
    from management groups that contain the given subscription, as well as any applied to objects
    contained within the subscription. If $filter=atScope() is provided, the returned list includes
    all policy assignments that apply to the subscription, which is everything in the unfiltered
    list except those applied to objects contained within the subscription. If
    $filter=policyDefinitionId eq '{value}' is provided, the returned list includes all policy
    assignments of the policy definition whose id is {value}.

        :param filter: The filter to apply on the operation. Valid values for $filter are: 'atScope()'
     or 'policyDefinitionId eq '{value}''. If $filter is not provided, no filtering is performed.
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either PolicyAssignmentListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignmentListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignmentListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('PolicyAssignmentListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments'}  # type: ignore

    def delete_by_id(
        self,
        policy_assignment_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PolicyAssignment"
        """Deletes a policy assignment.

        This operation deletes the policy with the given ID. Policy assignment IDs have this format:
        '{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'. Valid
        formats for {scope} are: '/providers/Microsoft.Management/managementGroups/{managementGroup}'
        (management group), '/subscriptions/{subscriptionId}' (subscription),
        '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}' (resource group), or
        '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/[{parentResourcePath}/]{resourceType}/{resourceName}'
        (resource).

        :param policy_assignment_id: The ID of the policy assignment to delete. Use the format
         '{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'.
        :type policy_assignment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PolicyAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignment or None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignment"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"

        # Construct URL
        url = self.delete_by_id.metadata['url']  # type: ignore
        path_format_arguments = {
            'policyAssignmentId': self._serialize.url("policy_assignment_id", policy_assignment_id, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('PolicyAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    delete_by_id.metadata = {'url': '/{policyAssignmentId}'}  # type: ignore

    def create_by_id(
        self,
        policy_assignment_id,  # type: str
        parameters,  # type: "models.PolicyAssignment"
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PolicyAssignment"
        """Creates or updates a policy assignment.

        This operation creates or updates the policy assignment with the given ID. Policy assignments
        made on a scope apply to all resources contained in that scope. For example, when you assign a
        policy to a resource group that policy applies to all resources in the group. Policy assignment
        IDs have this format:
        '{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'. Valid
        scopes are: management group (format:
        '/providers/Microsoft.Management/managementGroups/{managementGroup}'), subscription (format:
        '/subscriptions/{subscriptionId}'), resource group (format:
        '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}', or resource (format:
        '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/[{parentResourcePath}/]{resourceType}/{resourceName}'.

        :param policy_assignment_id: The ID of the policy assignment to create. Use the format
         '{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'.
        :type policy_assignment_id: str
        :param parameters: Parameters for policy assignment.
        :type parameters: ~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignment
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PolicyAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignment"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self.create_by_id.metadata['url']  # type: ignore
        path_format_arguments = {
            'policyAssignmentId': self._serialize.url("policy_assignment_id", policy_assignment_id, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(parameters, 'PolicyAssignment')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('PolicyAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_by_id.metadata = {'url': '/{policyAssignmentId}'}  # type: ignore

    def get_by_id(
        self,
        policy_assignment_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PolicyAssignment"
        """Retrieves the policy assignment with the given ID.

        The operation retrieves the policy assignment with the given ID. Policy assignment IDs have
        this format:
        '{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'. Valid
        scopes are: management group (format:
        '/providers/Microsoft.Management/managementGroups/{managementGroup}'), subscription (format:
        '/subscriptions/{subscriptionId}'), resource group (format:
        '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}', or resource (format:
        '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/[{parentResourcePath}/]{resourceType}/{resourceName}'.

        :param policy_assignment_id: The ID of the policy assignment to get. Use the format
         '{scope}/providers/Microsoft.Authorization/policyAssignments/{policyAssignmentName}'.
        :type policy_assignment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PolicyAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.policy.v2019_01_01.models.PolicyAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PolicyAssignment"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-01-01"

        # Construct URL
        url = self.get_by_id.metadata['url']  # type: ignore
        path_format_arguments = {
            'policyAssignmentId': self._serialize.url("policy_assignment_id", policy_assignment_id, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('PolicyAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_by_id.metadata = {'url': '/{policyAssignmentId}'}  # type: ignore
