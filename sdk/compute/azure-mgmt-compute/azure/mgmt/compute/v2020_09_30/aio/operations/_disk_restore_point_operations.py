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
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class DiskRestorePointOperations:
    """DiskRestorePointOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.compute.v2020_09_30.models
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
        restore_point_collection_name: str,
        vm_restore_point_name: str,
        disk_restore_point_name: str,
        **kwargs
    ) -> "_models.DiskRestorePoint":
        """Get disk restorePoint resource.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param restore_point_collection_name: The name of the restore point collection that the disk
         restore point belongs. Supported characters for the name are a-z, A-Z, 0-9 and _. The maximum
         name length is 80 characters.
        :type restore_point_collection_name: str
        :param vm_restore_point_name: The name of the vm restore point that the disk disk restore point
         belongs. Supported characters for the name are a-z, A-Z, 0-9 and _. The maximum name length is
         80 characters.
        :type vm_restore_point_name: str
        :param disk_restore_point_name: The name of the disk restore point created. Supported
         characters for the name are a-z, A-Z, 0-9 and _. The maximum name length is 80 characters.
        :type disk_restore_point_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DiskRestorePoint, or the result of cls(response)
        :rtype: ~azure.mgmt.compute.v2020_09_30.models.DiskRestorePoint
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DiskRestorePoint"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-09-30"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'restorePointCollectionName': self._serialize.url("restore_point_collection_name", restore_point_collection_name, 'str'),
            'vmRestorePointName': self._serialize.url("vm_restore_point_name", vm_restore_point_name, 'str'),
            'diskRestorePointName': self._serialize.url("disk_restore_point_name", disk_restore_point_name, 'str'),
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

        deserialized = self._deserialize('DiskRestorePoint', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/restorePointCollections/{restorePointCollectionName}/restorePoints/{vmRestorePointName}/diskRestorePoints/{diskRestorePointName}'}  # type: ignore

    def list_by_restore_point(
        self,
        resource_group_name: str,
        restore_point_collection_name: str,
        vm_restore_point_name: str,
        **kwargs
    ) -> AsyncIterable["_models.DiskRestorePointList"]:
        """Lists diskRestorePoints under a vmRestorePoint.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param restore_point_collection_name: The name of the restore point collection that the disk
         restore point belongs. Supported characters for the name are a-z, A-Z, 0-9 and _. The maximum
         name length is 80 characters.
        :type restore_point_collection_name: str
        :param vm_restore_point_name: The name of the vm restore point that the disk disk restore point
         belongs. Supported characters for the name are a-z, A-Z, 0-9 and _. The maximum name length is
         80 characters.
        :type vm_restore_point_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DiskRestorePointList or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.compute.v2020_09_30.models.DiskRestorePointList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DiskRestorePointList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-09-30"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_restore_point.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'restorePointCollectionName': self._serialize.url("restore_point_collection_name", restore_point_collection_name, 'str'),
                    'vmRestorePointName': self._serialize.url("vm_restore_point_name", vm_restore_point_name, 'str'),
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
            deserialized = self._deserialize('DiskRestorePointList', pipeline_response)
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
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_restore_point.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/restorePointCollections/{restorePointCollectionName}/restorePoints/{vmRestorePointName}/diskRestorePoints'}  # type: ignore
