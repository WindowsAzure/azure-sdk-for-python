# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.core.polling import LROPoller, NoPolling, PollingMethod
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.core.polling.arm_polling import ARMPolling

from .. import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class PrivateEndpointConnectionsOperations(object):
    """PrivateEndpointConnectionsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.keyvault.v2019_09_01.models
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

    def get(
        self,
        resource_group_name,  # type: str
        vault_name,  # type: str
        private_endpoint_connection_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PrivateEndpointConnection"
        """Gets the specified private endpoint connection associated with the key vault.

        :param resource_group_name: Name of the resource group that contains the key vault.
        :type resource_group_name: str
        :param vault_name: The name of the key vault.
        :type vault_name: str
        :param private_endpoint_connection_name: Name of the private endpoint connection associated
         with the key vault.
        :type private_endpoint_connection_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PrivateEndpointConnection or the result of cls(response)
        :rtype: ~azure.mgmt.keyvault.v2019_09_01.models.PrivateEndpointConnection
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PrivateEndpointConnection"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})
        api_version = "2019-09-01"

        # Construct URL
        url = self.get.metadata['url']
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
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('PrivateEndpointConnection', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections/{privateEndpointConnectionName}'}

    def put(
        self,
        resource_group_name,  # type: str
        vault_name,  # type: str
        private_endpoint_connection_name,  # type: str
        private_endpoint=None,  # type: Optional["models.PrivateEndpoint"]
        private_link_service_connection_state=None,  # type: Optional["models.PrivateLinkServiceConnectionState"]
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PrivateEndpointConnection"
        """Updates the specified private endpoint connection associated with the key vault.

        :param resource_group_name: Name of the resource group that contains the key vault.
        :type resource_group_name: str
        :param vault_name: The name of the key vault.
        :type vault_name: str
        :param private_endpoint_connection_name: Name of the private endpoint connection associated
         with the key vault.
        :type private_endpoint_connection_name: str
        :param private_endpoint: Properties of the private endpoint object.
        :type private_endpoint: ~azure.mgmt.keyvault.v2019_09_01.models.PrivateEndpoint
        :param private_link_service_connection_state: Approval state of the private link connection.
        :type private_link_service_connection_state: ~azure.mgmt.keyvault.v2019_09_01.models.PrivateLinkServiceConnectionState
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PrivateEndpointConnection or the result of cls(response)
        :rtype: ~azure.mgmt.keyvault.v2019_09_01.models.PrivateEndpointConnection
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PrivateEndpointConnection"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})

        _properties = models.PrivateEndpointConnection(private_endpoint=private_endpoint, private_link_service_connection_state=private_link_service_connection_state)
        api_version = "2019-09-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self.put.metadata['url']
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
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_properties, 'PrivateEndpointConnection')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
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
    put.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections/{privateEndpointConnectionName}'}

    def _delete_initial(
        self,
        resource_group_name,  # type: str
        vault_name,  # type: str
        private_endpoint_connection_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PrivateEndpointConnection"
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PrivateEndpointConnection"]
        error_map = kwargs.pop('error_map', {404: ResourceNotFoundError, 409: ResourceExistsError})
        api_version = "2019-09-01"

        # Construct URL
        url = self._delete_initial.metadata['url']
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
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
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
    _delete_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections/{privateEndpointConnectionName}'}

    def begin_delete(
        self,
        resource_group_name,  # type: str
        vault_name,  # type: str
        private_endpoint_connection_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.PrivateEndpointConnection"
        """Deletes the specified private endpoint connection associated with the key vault.

        :param resource_group_name: Name of the resource group that contains the key vault.
        :type resource_group_name: str
        :param vault_name: The name of the key vault.
        :type vault_name: str
        :param private_endpoint_connection_name: Name of the private endpoint connection associated
     with the key vault.
        :type private_endpoint_connection_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :return: An instance of LROPoller that returns PrivateEndpointConnection
        :rtype: ~azure.core.polling.LROPoller[~azure.mgmt.keyvault.v2019_09_01.models.PrivateEndpointConnection]

        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, PollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.PrivateEndpointConnection"]
        raw_result = self._delete_initial(
            resource_group_name=resource_group_name,
            vault_name=vault_name,
            private_endpoint_connection_name=private_endpoint_connection_name,
            cls=lambda x,y,z: x,
            **kwargs
        )

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('PrivateEndpointConnection', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        lro_delay = kwargs.get(
            'polling_interval',
            self._config.polling_interval
        )
        if polling is True: polling_method = ARMPolling(lro_delay,  **kwargs)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/privateEndpointConnections/{privateEndpointConnectionName}'}
