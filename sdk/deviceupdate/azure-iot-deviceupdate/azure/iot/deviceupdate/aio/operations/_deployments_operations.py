# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, AsyncIterable, Callable, Dict, Generic, Optional, TypeVar
import warnings

from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class DeploymentsOperations:
    """DeploymentsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.iot.deviceupdate.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def get_all_deployments(
        self,
        filter: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["_models.PageableListOfDeployments"]:
        """Gets a list of deployments.

        :param filter: Restricts the set of deployments returned. You can filter on update Provider,
         Name and Version property.
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either PageableListOfDeployments or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.iot.deviceupdate.models.PageableListOfDeployments]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.PageableListOfDeployments"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.get_all_deployments.metadata['url']  # type: ignore
                path_format_arguments = {
                    'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
                    'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                path_format_arguments = {
                    'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
                    'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
                }
                url = self._client.format_url(url, **path_format_arguments)
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('PageableListOfDeployments', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    get_all_deployments.metadata = {'url': '/deviceupdate/{instanceId}/v2/management/deployments'}  # type: ignore

    async def get_deployment(
        self,
        deployment_id: str,
        **kwargs
    ) -> "_models.Deployment":
        """Gets the properties of a deployment.

        :param deployment_id: Deployment identifier.
        :type deployment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Deployment, or the result of cls(response)
        :rtype: ~azure.iot.deviceupdate.models.Deployment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Deployment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        # Construct URL
        url = self.get_deployment.metadata['url']  # type: ignore
        path_format_arguments = {
            'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
            'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
            'deploymentId': self._serialize.url("deployment_id", deployment_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('Deployment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_deployment.metadata = {'url': '/deviceupdate/{instanceId}/v2/management/deployments/{deploymentId}'}  # type: ignore

    async def create_or_update_deployment(
        self,
        deployment_id: str,
        deployment: "_models.Deployment",
        **kwargs
    ) -> "_models.Deployment":
        """Creates or updates a deployment.

        :param deployment_id: Deployment identifier.
        :type deployment_id: str
        :param deployment: The deployment properties.
        :type deployment: ~azure.iot.deviceupdate.models.Deployment
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Deployment, or the result of cls(response)
        :rtype: ~azure.iot.deviceupdate.models.Deployment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Deployment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create_or_update_deployment.metadata['url']  # type: ignore
        path_format_arguments = {
            'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
            'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
            'deploymentId': self._serialize.url("deployment_id", deployment_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(deployment, 'Deployment')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('Deployment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_or_update_deployment.metadata = {'url': '/deviceupdate/{instanceId}/v2/management/deployments/{deploymentId}'}  # type: ignore

    async def delete_deployment(
        self,
        deployment_id: str,
        **kwargs
    ) -> None:
        """Deletes a deployment.

        :param deployment_id: Deployment identifier.
        :type deployment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        # Construct URL
        url = self.delete_deployment.metadata['url']  # type: ignore
        path_format_arguments = {
            'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
            'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
            'deploymentId': self._serialize.url("deployment_id", deployment_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if cls:
            return cls(pipeline_response, None, {})

    delete_deployment.metadata = {'url': '/deviceupdate/{instanceId}/v2/management/deployments/{deploymentId}'}  # type: ignore

    async def get_deployment_status(
        self,
        deployment_id: str,
        **kwargs
    ) -> "_models.DeploymentStatus":
        """Gets the status of a deployment including a breakdown of how many devices in the deployment are
        in progress, completed, or failed.

        :param deployment_id: Deployment identifier.
        :type deployment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DeploymentStatus, or the result of cls(response)
        :rtype: ~azure.iot.deviceupdate.models.DeploymentStatus
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DeploymentStatus"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        # Construct URL
        url = self.get_deployment_status.metadata['url']  # type: ignore
        path_format_arguments = {
            'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
            'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
            'deploymentId': self._serialize.url("deployment_id", deployment_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('DeploymentStatus', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_deployment_status.metadata = {'url': '/deviceupdate/{instanceId}/v2/management/deployments/{deploymentId}/status'}  # type: ignore

    def get_deployment_devices(
        self,
        deployment_id: str,
        filter: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["_models.PageableListOfDeploymentDeviceStates"]:
        """Gets a list of devices in a deployment along with their state. Useful for getting a list of
        failed devices.

        :param deployment_id: Deployment identifier.
        :type deployment_id: str
        :param filter: Restricts the set of deployment device states returned. You can filter on
         deviceId and/or deviceState.
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either PageableListOfDeploymentDeviceStates or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.iot.deviceupdate.models.PageableListOfDeploymentDeviceStates]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.PageableListOfDeploymentDeviceStates"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.get_deployment_devices.metadata['url']  # type: ignore
                path_format_arguments = {
                    'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
                    'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
                    'deploymentId': self._serialize.url("deployment_id", deployment_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                path_format_arguments = {
                    'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
                    'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
                    'deploymentId': self._serialize.url("deployment_id", deployment_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('PageableListOfDeploymentDeviceStates', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    get_deployment_devices.metadata = {'url': '/deviceupdate/{instanceId}/v2/management/deployments/{deploymentId}/devicestates'}  # type: ignore

    async def cancel_deployment(
        self,
        deployment_id: str,
        **kwargs
    ) -> "_models.Deployment":
        """Cancels a deployment.

        :param deployment_id: Deployment identifier.
        :type deployment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Deployment, or the result of cls(response)
        :rtype: ~azure.iot.deviceupdate.models.Deployment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Deployment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        action = "cancel"
        accept = "application/json"

        # Construct URL
        url = self.cancel_deployment.metadata['url']  # type: ignore
        path_format_arguments = {
            'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
            'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
            'deploymentId': self._serialize.url("deployment_id", deployment_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['action'] = self._serialize.query("action", action, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('Deployment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    cancel_deployment.metadata = {'url': '/deviceupdate/{instanceId}/v2/management/deployments/{deploymentId}'}  # type: ignore

    async def retry_deployment(
        self,
        deployment_id: str,
        **kwargs
    ) -> "_models.Deployment":
        """Retries a deployment with failed devices.

        :param deployment_id: Deployment identifier.
        :type deployment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Deployment, or the result of cls(response)
        :rtype: ~azure.iot.deviceupdate.models.Deployment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Deployment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        action = "retry"
        accept = "application/json"

        # Construct URL
        url = self.retry_deployment.metadata['url']  # type: ignore
        path_format_arguments = {
            'accountEndpoint': self._serialize.url("self._config.account_endpoint", self._config.account_endpoint, 'str', skip_quote=True),
            'instanceId': self._serialize.url("self._config.instance_id", self._config.instance_id, 'str', skip_quote=True),
            'deploymentId': self._serialize.url("deployment_id", deployment_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['action'] = self._serialize.query("action", action, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('Deployment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    retry_deployment.metadata = {'url': '/deviceupdate/{instanceId}/v2/management/deployments/{deploymentId}'}  # type: ignore
