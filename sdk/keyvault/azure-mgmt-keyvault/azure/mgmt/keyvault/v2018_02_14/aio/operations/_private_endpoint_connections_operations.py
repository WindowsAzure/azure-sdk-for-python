# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.core.polling import AsyncLROPoller, AsyncNoPolling, AsyncPollingMethod
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.core.polling.async_arm_polling import AsyncARMPolling

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class PrivateEndpointConnectionsOperations:
    """PrivateEndpointConnectionsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.keyvault.models
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
        resource_group_name: str,
        vault_name: str,
        private_endpoint_connection_name: str,
        **kwargs
    ) -> "_models.PrivateEndpointConnection":
        """Gets the specified private endpoint connection associated with the key vault.

        :param resource_group_name: Name of the resource group that contains the key vault.
        :type resource_group_name: str
        :param vault_name: The name of the key vault.
        :type vault_name: str
        :param private_endpoint_connection_name: Name of the private endpoint connection associated
         with the key vault.
        :type private_endpoint_connection_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PrivateEndpointConnection, or the result of cls(response)
        :rtype: ~azure.mgmt.keyvault.models.PrivateEndpointConnection
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.PrivateEndpointConnection"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-02-14"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'vaultName': self._serialize.url("vault_name", vault_name, 'str', pattern=r'^[a-zA-Z0-9-]{3,24}$'),
            'privateEndpointConnectionName': self._serialize.url("private_endpoint_connection_name", private_endpoint_connection_name, 'str'),
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
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('PrivateEndpointConnection', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections/{privateEndpointConnectionName}'}  # type: ignore

    async def put(
        self,
        resource_group_name: str,
        vault_name: str,
        private_endpoint_connection_name: str,
        properties: "_models.PrivateEndpointConnection",
        **kwargs
    ) -> "_models.PrivateEndpointConnection":
        """Updates the specified private endpoint connection associated with the key vault.

        :param resource_group_name: Name of the resource group that contains the key vault.
        :type resource_group_name: str
        :param vault_name: The name of the key vault.
        :type vault_name: str
        :param private_endpoint_connection_name: Name of the private endpoint connection associated
         with the key vault.
        :type private_endpoint_connection_name: str
        :param properties: The intended state of private endpoint connection.
        :type properties: ~azure.mgmt.keyvault.models.PrivateEndpointConnection
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PrivateEndpointConnection, or the result of cls(response)
        :rtype: ~azure.mgmt.keyvault.models.PrivateEndpointConnection
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.PrivateEndpointConnection"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-02-14"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.put.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'vaultName': self._serialize.url("vault_name", vault_name, 'str', pattern=r'^[a-zA-Z0-9-]{3,24}$'),
            'privateEndpointConnectionName': self._serialize.url("private_endpoint_connection_name", private_endpoint_connection_name, 'str'),
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
        body_content = self._serialize.body(properties, 'PrivateEndpointConnection')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        response_headers = {}
        response_headers['Retry-After']=self._deserialize('int', response.headers.get('Retry-After'))
        response_headers['Azure-AsyncOperation']=self._deserialize('str', response.headers.get('Azure-AsyncOperation'))
        deserialized = self._deserialize('PrivateEndpointConnection', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    put.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections/{privateEndpointConnectionName}'}  # type: ignore

    async def _delete_initial(
        self,
        resource_group_name: str,
        vault_name: str,
        private_endpoint_connection_name: str,
        **kwargs
    ) -> Optional["_models.PrivateEndpointConnection"]:
        cls = kwargs.pop('cls', None)  # type: ClsType[Optional["_models.PrivateEndpointConnection"]]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-02-14"
        accept = "application/json"

        # Construct URL
        url = self._delete_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'vaultName': self._serialize.url("vault_name", vault_name, 'str', pattern=r'^[a-zA-Z0-9-]{3,24}$'),
            'privateEndpointConnectionName': self._serialize.url("private_endpoint_connection_name", private_endpoint_connection_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        response_headers = {}
        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('PrivateEndpointConnection', pipeline_response)

        if response.status_code == 202:
            response_headers['Retry-After']=self._deserialize('int', response.headers.get('Retry-After'))
            response_headers['Location']=self._deserialize('str', response.headers.get('Location'))

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    _delete_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections/{privateEndpointConnectionName}'}  # type: ignore

    async def begin_delete(
        self,
        resource_group_name: str,
        vault_name: str,
        private_endpoint_connection_name: str,
        **kwargs
    ) -> AsyncLROPoller["_models.PrivateEndpointConnection"]:
        """Deletes the specified private endpoint connection associated with the key vault.

        :param resource_group_name: Name of the resource group that contains the key vault.
        :type resource_group_name: str
        :param vault_name: The name of the key vault.
        :type vault_name: str
        :param private_endpoint_connection_name: Name of the private endpoint connection associated
         with the key vault.
        :type private_endpoint_connection_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: Pass in True if you'd like the AsyncARMPolling polling method,
         False for no polling, or your own initialized polling object for a personal polling strategy.
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either PrivateEndpointConnection or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.mgmt.keyvault.models.PrivateEndpointConnection]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.PrivateEndpointConnection"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._delete_initial(
                resource_group_name=resource_group_name,
                vault_name=vault_name,
                private_endpoint_connection_name=private_endpoint_connection_name,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('PrivateEndpointConnection', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'vaultName': self._serialize.url("vault_name", vault_name, 'str', pattern=r'^[a-zA-Z0-9-]{3,24}$'),
            'privateEndpointConnectionName': self._serialize.url("private_endpoint_connection_name", private_endpoint_connection_name, 'str'),
        }

        if polling is True: polling_method = AsyncARMPolling(lro_delay, path_format_arguments=path_format_arguments,  **kwargs)
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        if cont_token:
            return AsyncLROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return AsyncLROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections/{privateEndpointConnectionName}'}  # type: ignore
