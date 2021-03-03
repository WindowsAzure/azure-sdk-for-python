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

class ManagedPrivateEndpointsOperations:
    """ManagedPrivateEndpointsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.synapse.managedprivateendpoints.models
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

    async def get(
        self,
        managed_private_endpoint_name: str,
        managed_virtual_network_name: str = "default",
        **kwargs
    ) -> "_models.ManagedPrivateEndpoint":
        """Get Managed Private Endpoints.

        :param managed_private_endpoint_name: Managed private endpoint name.
        :type managed_private_endpoint_name: str
        :param managed_virtual_network_name: Managed virtual network name.
        :type managed_virtual_network_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ManagedPrivateEndpoint, or the result of cls(response)
        :rtype: ~azure.synapse.managedprivateendpoints.models.ManagedPrivateEndpoint
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ManagedPrivateEndpoint"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'managedVirtualNetworkName': self._serialize.url("managed_virtual_network_name", managed_virtual_network_name, 'str'),
            'managedPrivateEndpointName': self._serialize.url("managed_private_endpoint_name", managed_private_endpoint_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('ManagedPrivateEndpoint', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/managedVirtualNetworks/{managedVirtualNetworkName}/managedPrivateEndpoints/{managedPrivateEndpointName}'}  # type: ignore

    async def create(
        self,
        managed_private_endpoint_name: str,
        managed_virtual_network_name: str = "default",
        properties: Optional["_models.ManagedPrivateEndpointProperties"] = None,
        **kwargs
    ) -> "_models.ManagedPrivateEndpoint":
        """Create Managed Private Endpoints.

        :param managed_private_endpoint_name: Managed private endpoint name.
        :type managed_private_endpoint_name: str
        :param managed_virtual_network_name: Managed virtual network name.
        :type managed_virtual_network_name: str
        :param properties: Managed private endpoint properties.
        :type properties: ~azure.synapse.managedprivateendpoints.models.ManagedPrivateEndpointProperties
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ManagedPrivateEndpoint, or the result of cls(response)
        :rtype: ~azure.synapse.managedprivateendpoints.models.ManagedPrivateEndpoint
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ManagedPrivateEndpoint"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        _managed_private_endpoint = _models.ManagedPrivateEndpoint(properties=properties)
        api_version = "2019-06-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'managedVirtualNetworkName': self._serialize.url("managed_virtual_network_name", managed_virtual_network_name, 'str'),
            'managedPrivateEndpointName': self._serialize.url("managed_private_endpoint_name", managed_private_endpoint_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_managed_private_endpoint, 'ManagedPrivateEndpoint')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('ManagedPrivateEndpoint', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create.metadata = {'url': '/managedVirtualNetworks/{managedVirtualNetworkName}/managedPrivateEndpoints/{managedPrivateEndpointName}'}  # type: ignore

    async def delete(
        self,
        managed_private_endpoint_name: str,
        managed_virtual_network_name: str = "default",
        **kwargs
    ) -> None:
        """Delete Managed Private Endpoints.

        :param managed_private_endpoint_name: Managed private endpoint name.
        :type managed_private_endpoint_name: str
        :param managed_virtual_network_name: Managed virtual network name.
        :type managed_virtual_network_name: str
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
        api_version = "2019-06-01-preview"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'managedVirtualNetworkName': self._serialize.url("managed_virtual_network_name", managed_virtual_network_name, 'str'),
            'managedPrivateEndpointName': self._serialize.url("managed_private_endpoint_name", managed_private_endpoint_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [202, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/managedVirtualNetworks/{managedVirtualNetworkName}/managedPrivateEndpoints/{managedPrivateEndpointName}'}  # type: ignore

    def list(
        self,
        managed_virtual_network_name: str = "default",
        **kwargs
    ) -> AsyncIterable["_models.ManagedPrivateEndpointListResponse"]:
        """List Managed Private Endpoints.

        :param managed_virtual_network_name: Managed virtual network name.
        :type managed_virtual_network_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either ManagedPrivateEndpointListResponse or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.synapse.managedprivateendpoints.models.ManagedPrivateEndpointListResponse]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ManagedPrivateEndpointListResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                    'managedVirtualNetworkName': self._serialize.url("managed_virtual_network_name", managed_virtual_network_name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                path_format_arguments = {
                    'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                    'managedVirtualNetworkName': self._serialize.url("managed_virtual_network_name", managed_virtual_network_name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('ManagedPrivateEndpointListResponse', pipeline_response)
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
    list.metadata = {'url': '/managedVirtualNetworks/{managedVirtualNetworkName}/managedPrivateEndpoints'}  # type: ignore
