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

class DeploymentOperationsOperations(object):
    """DeploymentOperationsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.resource.resources.v2019_10_01.models
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

    def get_at_scope(
        self,
        scope,  # type: str
        deployment_name,  # type: str
        operation_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.DeploymentOperation"
        """Gets a deployments operation.

        :param scope: The resource scope.
        :type scope: str
        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param operation_id: The ID of the operation to get.
        :type operation_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DeploymentOperation, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperation
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperation"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        # Construct URL
        url = self.get_at_scope.metadata['url']  # type: ignore
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'operationId': self._serialize.url("operation_id", operation_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DeploymentOperation', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_at_scope.metadata = {'url': '/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}/operations/{operationId}'}  # type: ignore

    def list_at_scope(
        self,
        scope,  # type: str
        deployment_name,  # type: str
        top=None,  # type: Optional[int]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.DeploymentOperationsListResult"]
        """Gets all deployments operations for a deployment.

        :param scope: The resource scope.
        :type scope: str
        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param top: The number of results to return.
        :type top: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DeploymentOperationsListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperationsListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperationsListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            if not next_link:
                # Construct URL
                url = self.list_at_scope.metadata['url']  # type: ignore
                path_format_arguments = {
                    'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
                    'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('DeploymentOperationsListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_at_scope.metadata = {'url': '/{scope}/providers/Microsoft.Resources/deployments/{deploymentName}/operations'}  # type: ignore

    def get_at_tenant_scope(
        self,
        deployment_name,  # type: str
        operation_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.DeploymentOperation"
        """Gets a deployments operation.

        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param operation_id: The ID of the operation to get.
        :type operation_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DeploymentOperation, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperation
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperation"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        # Construct URL
        url = self.get_at_tenant_scope.metadata['url']  # type: ignore
        path_format_arguments = {
            'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'operationId': self._serialize.url("operation_id", operation_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DeploymentOperation', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_at_tenant_scope.metadata = {'url': '/providers/Microsoft.Resources/deployments/{deploymentName}/operations/{operationId}'}  # type: ignore

    def list_at_tenant_scope(
        self,
        deployment_name,  # type: str
        top=None,  # type: Optional[int]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.DeploymentOperationsListResult"]
        """Gets all deployments operations for a deployment.

        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param top: The number of results to return.
        :type top: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DeploymentOperationsListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperationsListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperationsListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            if not next_link:
                # Construct URL
                url = self.list_at_tenant_scope.metadata['url']  # type: ignore
                path_format_arguments = {
                    'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('DeploymentOperationsListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_at_tenant_scope.metadata = {'url': '/providers/Microsoft.Resources/deployments/{deploymentName}/operations'}  # type: ignore

    def get_at_management_group_scope(
        self,
        group_id,  # type: str
        deployment_name,  # type: str
        operation_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.DeploymentOperation"
        """Gets a deployments operation.

        :param group_id: The management group ID.
        :type group_id: str
        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param operation_id: The ID of the operation to get.
        :type operation_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DeploymentOperation, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperation
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperation"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        # Construct URL
        url = self.get_at_management_group_scope.metadata['url']  # type: ignore
        path_format_arguments = {
            'groupId': self._serialize.url("group_id", group_id, 'str', max_length=90, min_length=1),
            'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'operationId': self._serialize.url("operation_id", operation_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DeploymentOperation', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_at_management_group_scope.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}/providers/Microsoft.Resources/deployments/{deploymentName}/operations/{operationId}'}  # type: ignore

    def list_at_management_group_scope(
        self,
        group_id,  # type: str
        deployment_name,  # type: str
        top=None,  # type: Optional[int]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.DeploymentOperationsListResult"]
        """Gets all deployments operations for a deployment.

        :param group_id: The management group ID.
        :type group_id: str
        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param top: The number of results to return.
        :type top: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DeploymentOperationsListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperationsListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperationsListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            if not next_link:
                # Construct URL
                url = self.list_at_management_group_scope.metadata['url']  # type: ignore
                path_format_arguments = {
                    'groupId': self._serialize.url("group_id", group_id, 'str', max_length=90, min_length=1),
                    'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('DeploymentOperationsListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_at_management_group_scope.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}/providers/Microsoft.Resources/deployments/{deploymentName}/operations'}  # type: ignore

    def get_at_subscription_scope(
        self,
        deployment_name,  # type: str
        operation_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.DeploymentOperation"
        """Gets a deployments operation.

        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param operation_id: The ID of the operation to get.
        :type operation_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DeploymentOperation, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperation
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperation"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        # Construct URL
        url = self.get_at_subscription_scope.metadata['url']  # type: ignore
        path_format_arguments = {
            'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'operationId': self._serialize.url("operation_id", operation_id, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DeploymentOperation', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_at_subscription_scope.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Resources/deployments/{deploymentName}/operations/{operationId}'}  # type: ignore

    def list_at_subscription_scope(
        self,
        deployment_name,  # type: str
        top=None,  # type: Optional[int]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.DeploymentOperationsListResult"]
        """Gets all deployments operations for a deployment.

        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param top: The number of results to return.
        :type top: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DeploymentOperationsListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperationsListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperationsListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            if not next_link:
                # Construct URL
                url = self.list_at_subscription_scope.metadata['url']  # type: ignore
                path_format_arguments = {
                    'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('DeploymentOperationsListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_at_subscription_scope.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Resources/deployments/{deploymentName}/operations'}  # type: ignore

    def get(
        self,
        resource_group_name,  # type: str
        deployment_name,  # type: str
        operation_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.DeploymentOperation"
        """Gets a deployments operation.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param operation_id: The ID of the operation to get.
        :type operation_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DeploymentOperation, or the result of cls(response)
        :rtype: ~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperation
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperation"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'operationId': self._serialize.url("operation_id", operation_id, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DeploymentOperation', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/deployments/{deploymentName}/operations/{operationId}'}  # type: ignore

    def list(
        self,
        resource_group_name,  # type: str
        deployment_name,  # type: str
        top=None,  # type: Optional[int]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.DeploymentOperationsListResult"]
        """Gets all deployments operations for a deployment.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param deployment_name: The name of the deployment.
        :type deployment_name: str
        :param top: The number of results to return.
        :type top: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DeploymentOperationsListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.resource.resources.v2019_10_01.models.DeploymentOperationsListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.DeploymentOperationsListResult"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-10-01"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'deploymentName': self._serialize.url("deployment_name", deployment_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('DeploymentOperationsListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/deployments/{deploymentName}/operations'}  # type: ignore
