# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, AsyncIterable, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.core.polling import AsyncLROPoller, AsyncNoPolling, AsyncPollingMethod
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.core.polling.async_arm_polling import AsyncARMPolling

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class BackupsOperations:
    """BackupsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.netapp.models
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

    async def get_status(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        **kwargs: Any
    ) -> "_models.BackupStatus":
        """Get volume's backup status.

        Get the status of the backup for a volume.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param account_name: The name of the NetApp account.
        :type account_name: str
        :param pool_name: The name of the capacity pool.
        :type pool_name: str
        :param volume_name: The name of the volume.
        :type volume_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: BackupStatus, or the result of cls(response)
        :rtype: ~azure.mgmt.netapp.models.BackupStatus
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BackupStatus"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-02-01"
        accept = "application/json"

        # Construct URL
        url = self.get_status.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
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

        deserialized = self._deserialize('BackupStatus', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_status.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backupStatus'}  # type: ignore

    def list(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        **kwargs: Any
    ) -> AsyncIterable["_models.BackupsList"]:
        """List Backups.

        List all backups for a volume.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param account_name: The name of the NetApp account.
        :type account_name: str
        :param pool_name: The name of the capacity pool.
        :type pool_name: str
        :param volume_name: The name of the volume.
        :type volume_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either BackupsList or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.netapp.models.BackupsList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BackupsList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-02-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'accountName': self._serialize.url("account_name", account_name, 'str'),
                    'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
                    'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('BackupsList', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backups'}  # type: ignore

    async def get(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        backup_name: str,
        **kwargs: Any
    ) -> "_models.Backup":
        """Get a backup.

        Gets the specified backup of the volume.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param account_name: The name of the NetApp account.
        :type account_name: str
        :param pool_name: The name of the capacity pool.
        :type pool_name: str
        :param volume_name: The name of the volume.
        :type volume_name: str
        :param backup_name: The name of the backup.
        :type backup_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Backup, or the result of cls(response)
        :rtype: ~azure.mgmt.netapp.models.Backup
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Backup"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-02-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
            'backupName': self._serialize.url("backup_name", backup_name, 'str'),
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

        deserialized = self._deserialize('Backup', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backups/{backupName}'}  # type: ignore

    async def _create_initial(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        backup_name: str,
        body: "_models.Backup",
        **kwargs: Any
    ) -> Optional["_models.Backup"]:
        cls = kwargs.pop('cls', None)  # type: ClsType[Optional["_models.Backup"]]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-02-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self._create_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
            'backupName': self._serialize.url("backup_name", backup_name, 'str'),
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
        body_content = self._serialize.body(body, 'Backup')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201, 202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('Backup', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('Backup', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _create_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backups/{backupName}'}  # type: ignore

    async def begin_create(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        backup_name: str,
        body: "_models.Backup",
        **kwargs: Any
    ) -> AsyncLROPoller["_models.Backup"]:
        """Create a backup.

        Create a backup for the volume.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param account_name: The name of the NetApp account.
        :type account_name: str
        :param pool_name: The name of the capacity pool.
        :type pool_name: str
        :param volume_name: The name of the volume.
        :type volume_name: str
        :param backup_name: The name of the backup.
        :type backup_name: str
        :param body: Backup object supplied in the body of the operation.
        :type body: ~azure.mgmt.netapp.models.Backup
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: By default, your polling method will be AsyncARMPolling.
         Pass in False for this operation to not poll, or pass in your own initialized polling object for a personal polling strategy.
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either Backup or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.mgmt.netapp.models.Backup]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Backup"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._create_initial(
                resource_group_name=resource_group_name,
                account_name=account_name,
                pool_name=pool_name,
                volume_name=volume_name,
                backup_name=backup_name,
                body=body,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('Backup', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
            'backupName': self._serialize.url("backup_name", backup_name, 'str'),
        }

        if polling is True: polling_method = AsyncARMPolling(lro_delay, lro_options={'final-state-via': 'location'}, path_format_arguments=path_format_arguments,  **kwargs)
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
    begin_create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backups/{backupName}'}  # type: ignore

    async def _update_initial(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        backup_name: str,
        body: Optional["_models.BackupPatch"] = None,
        **kwargs: Any
    ) -> "_models.Backup":
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Backup"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-02-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self._update_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
            'backupName': self._serialize.url("backup_name", backup_name, 'str'),
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
        if body is not None:
            body_content = self._serialize.body(body, 'BackupPatch')
        else:
            body_content = None
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('Backup', pipeline_response)

        if response.status_code == 202:
            deserialized = self._deserialize('Backup', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _update_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backups/{backupName}'}  # type: ignore

    async def begin_update(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        backup_name: str,
        body: Optional["_models.BackupPatch"] = None,
        **kwargs: Any
    ) -> AsyncLROPoller["_models.Backup"]:
        """Patch a backup.

        Patch a backup for the volume.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param account_name: The name of the NetApp account.
        :type account_name: str
        :param pool_name: The name of the capacity pool.
        :type pool_name: str
        :param volume_name: The name of the volume.
        :type volume_name: str
        :param backup_name: The name of the backup.
        :type backup_name: str
        :param body: Backup object supplied in the body of the operation.
        :type body: ~azure.mgmt.netapp.models.BackupPatch
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: By default, your polling method will be AsyncARMPolling.
         Pass in False for this operation to not poll, or pass in your own initialized polling object for a personal polling strategy.
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either Backup or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.mgmt.netapp.models.Backup]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Backup"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._update_initial(
                resource_group_name=resource_group_name,
                account_name=account_name,
                pool_name=pool_name,
                volume_name=volume_name,
                backup_name=backup_name,
                body=body,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('Backup', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
            'backupName': self._serialize.url("backup_name", backup_name, 'str'),
        }

        if polling is True: polling_method = AsyncARMPolling(lro_delay, lro_options={'final-state-via': 'location'}, path_format_arguments=path_format_arguments,  **kwargs)
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
    begin_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backups/{backupName}'}  # type: ignore

    async def _delete_initial(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        backup_name: str,
        **kwargs: Any
    ) -> None:
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-02-01"

        # Construct URL
        url = self._delete_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
            'backupName': self._serialize.url("backup_name", backup_name, 'str'),
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

        if response.status_code not in [200, 202, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    _delete_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backups/{backupName}'}  # type: ignore

    async def begin_delete(
        self,
        resource_group_name: str,
        account_name: str,
        pool_name: str,
        volume_name: str,
        backup_name: str,
        **kwargs: Any
    ) -> AsyncLROPoller[None]:
        """Delete backup.

        Delete a backup of the volume.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param account_name: The name of the NetApp account.
        :type account_name: str
        :param pool_name: The name of the capacity pool.
        :type pool_name: str
        :param volume_name: The name of the volume.
        :type volume_name: str
        :param backup_name: The name of the backup.
        :type backup_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: By default, your polling method will be AsyncARMPolling.
         Pass in False for this operation to not poll, or pass in your own initialized polling object for a personal polling strategy.
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either None or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[None]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._delete_initial(
                resource_group_name=resource_group_name,
                account_name=account_name,
                pool_name=pool_name,
                volume_name=volume_name,
                backup_name=backup_name,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,63}$'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str', max_length=64, min_length=1, pattern=r'^[a-zA-Z][a-zA-Z0-9\-_]{0,63}$'),
            'backupName': self._serialize.url("backup_name", backup_name, 'str'),
        }

        if polling is True: polling_method = AsyncARMPolling(lro_delay, lro_options={'final-state-via': 'location'}, path_format_arguments=path_format_arguments,  **kwargs)
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
    begin_delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/capacityPools/{poolName}/volumes/{volumeName}/backups/{backupName}'}  # type: ignore
