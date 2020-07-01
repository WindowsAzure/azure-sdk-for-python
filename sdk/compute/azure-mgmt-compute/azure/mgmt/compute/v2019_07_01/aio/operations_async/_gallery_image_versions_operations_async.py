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
from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.core.polling import AsyncLROPoller, AsyncNoPolling, AsyncPollingMethod
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.core.polling.async_arm_polling import AsyncARMPolling

from ... import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class GalleryImageVersionsOperations:
    """GalleryImageVersionsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.compute.v2019_07_01.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    async def _create_or_update_initial(
        self,
        resource_group_name: str,
        gallery_name: str,
        gallery_image_name: str,
        gallery_image_version_name: str,
        gallery_image_version: "models.GalleryImageVersion",
        **kwargs
    ) -> "models.GalleryImageVersion":
        cls = kwargs.pop('cls', None)  # type: ClsType["models.GalleryImageVersion"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self._create_or_update_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
            'galleryImageName': self._serialize.url("gallery_image_name", gallery_image_name, 'str'),
            'galleryImageVersionName': self._serialize.url("gallery_image_version_name", gallery_image_version_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(gallery_image_version, 'GalleryImageVersion')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201, 202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('GalleryImageVersion', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('GalleryImageVersion', pipeline_response)

        if response.status_code == 202:
            deserialized = self._deserialize('GalleryImageVersion', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _create_or_update_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/images/{galleryImageName}/versions/{galleryImageVersionName}'}  # type: ignore

    async def begin_create_or_update(
        self,
        resource_group_name: str,
        gallery_name: str,
        gallery_image_name: str,
        gallery_image_version_name: str,
        gallery_image_version: "models.GalleryImageVersion",
        **kwargs
    ) -> AsyncLROPoller["models.GalleryImageVersion"]:
        """Create or update a gallery Image Version.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Image Gallery in which the Image Definition
     resides.
        :type gallery_name: str
        :param gallery_image_name: The name of the gallery Image Definition in which the Image Version
     is to be created.
        :type gallery_image_name: str
        :param gallery_image_version_name: The name of the gallery Image Version to be created. Needs
     to follow semantic version name pattern: The allowed characters are digit and period. Digits
     must be within the range of a 32-bit integer. Format:
     :code:`<MajorVersion>`.:code:`<MinorVersion>`.:code:`<Patch>`.
        :type gallery_image_version_name: str
        :param gallery_image_version: Parameters supplied to the create or update gallery Image Version
     operation.
        :type gallery_image_version: ~azure.mgmt.compute.v2019_07_01.models.GalleryImageVersion
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either GalleryImageVersion or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.mgmt.compute.v2019_07_01.models.GalleryImageVersion]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.GalleryImageVersion"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._create_or_update_initial(
                resource_group_name=resource_group_name,
                gallery_name=gallery_name,
                gallery_image_name=gallery_image_name,
                gallery_image_version_name=gallery_image_version_name,
                gallery_image_version=gallery_image_version,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('GalleryImageVersion', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        if polling is True: polling_method = AsyncARMPolling(lro_delay,  **kwargs)
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
    begin_create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/images/{galleryImageName}/versions/{galleryImageVersionName}'}  # type: ignore

    async def _update_initial(
        self,
        resource_group_name: str,
        gallery_name: str,
        gallery_image_name: str,
        gallery_image_version_name: str,
        gallery_image_version: "models.GalleryImageVersionUpdate",
        **kwargs
    ) -> "models.GalleryImageVersion":
        cls = kwargs.pop('cls', None)  # type: ClsType["models.GalleryImageVersion"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self._update_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
            'galleryImageName': self._serialize.url("gallery_image_name", gallery_image_name, 'str'),
            'galleryImageVersionName': self._serialize.url("gallery_image_version_name", gallery_image_version_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(gallery_image_version, 'GalleryImageVersionUpdate')
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('GalleryImageVersion', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _update_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/images/{galleryImageName}/versions/{galleryImageVersionName}'}  # type: ignore

    async def begin_update(
        self,
        resource_group_name: str,
        gallery_name: str,
        gallery_image_name: str,
        gallery_image_version_name: str,
        gallery_image_version: "models.GalleryImageVersionUpdate",
        **kwargs
    ) -> AsyncLROPoller["models.GalleryImageVersion"]:
        """Update a gallery Image Version.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Image Gallery in which the Image Definition
     resides.
        :type gallery_name: str
        :param gallery_image_name: The name of the gallery Image Definition in which the Image Version
     is to be updated.
        :type gallery_image_name: str
        :param gallery_image_version_name: The name of the gallery Image Version to be updated. Needs
     to follow semantic version name pattern: The allowed characters are digit and period. Digits
     must be within the range of a 32-bit integer. Format:
     :code:`<MajorVersion>`.:code:`<MinorVersion>`.:code:`<Patch>`.
        :type gallery_image_version_name: str
        :param gallery_image_version: Parameters supplied to the update gallery Image Version
     operation.
        :type gallery_image_version: ~azure.mgmt.compute.v2019_07_01.models.GalleryImageVersionUpdate
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either GalleryImageVersion or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.mgmt.compute.v2019_07_01.models.GalleryImageVersion]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.GalleryImageVersion"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._update_initial(
                resource_group_name=resource_group_name,
                gallery_name=gallery_name,
                gallery_image_name=gallery_image_name,
                gallery_image_version_name=gallery_image_version_name,
                gallery_image_version=gallery_image_version,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('GalleryImageVersion', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        if polling is True: polling_method = AsyncARMPolling(lro_delay,  **kwargs)
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
    begin_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/images/{galleryImageName}/versions/{galleryImageVersionName}'}  # type: ignore

    async def get(
        self,
        resource_group_name: str,
        gallery_name: str,
        gallery_image_name: str,
        gallery_image_version_name: str,
        expand: Optional[str] = "ReplicationStatus",
        **kwargs
    ) -> "models.GalleryImageVersion":
        """Retrieves information about a gallery Image Version.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Image Gallery in which the Image Definition
         resides.
        :type gallery_name: str
        :param gallery_image_name: The name of the gallery Image Definition in which the Image Version
         resides.
        :type gallery_image_name: str
        :param gallery_image_version_name: The name of the gallery Image Version to be retrieved.
        :type gallery_image_version_name: str
        :param expand: The expand expression to apply on the operation.
        :type expand: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: GalleryImageVersion, or the result of cls(response)
        :rtype: ~azure.mgmt.compute.v2019_07_01.models.GalleryImageVersion
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.GalleryImageVersion"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
            'galleryImageName': self._serialize.url("gallery_image_name", gallery_image_name, 'str'),
            'galleryImageVersionName': self._serialize.url("gallery_image_version_name", gallery_image_version_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if expand is not None:
            query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = 'application/json'

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('GalleryImageVersion', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/images/{galleryImageName}/versions/{galleryImageVersionName}'}  # type: ignore

    async def _delete_initial(
        self,
        resource_group_name: str,
        gallery_name: str,
        gallery_image_name: str,
        gallery_image_version_name: str,
        **kwargs
    ) -> None:
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01"

        # Construct URL
        url = self._delete_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
            'galleryImageName': self._serialize.url("gallery_image_name", gallery_image_name, 'str'),
            'galleryImageVersionName': self._serialize.url("gallery_image_version_name", gallery_image_version_name, 'str'),
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

    _delete_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/images/{galleryImageName}/versions/{galleryImageVersionName}'}  # type: ignore

    async def begin_delete(
        self,
        resource_group_name: str,
        gallery_name: str,
        gallery_image_name: str,
        gallery_image_version_name: str,
        **kwargs
    ) -> AsyncLROPoller[None]:
        """Delete a gallery Image Version.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Image Gallery in which the Image Definition
     resides.
        :type gallery_name: str
        :param gallery_image_name: The name of the gallery Image Definition in which the Image Version
     resides.
        :type gallery_image_name: str
        :param gallery_image_version_name: The name of the gallery Image Version to be deleted.
        :type gallery_image_version_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
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
                gallery_name=gallery_name,
                gallery_image_name=gallery_image_name,
                gallery_image_version_name=gallery_image_version_name,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        if polling is True: polling_method = AsyncARMPolling(lro_delay,  **kwargs)
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
    begin_delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/images/{galleryImageName}/versions/{galleryImageVersionName}'}  # type: ignore

    def list_by_gallery_image(
        self,
        resource_group_name: str,
        gallery_name: str,
        gallery_image_name: str,
        **kwargs
    ) -> AsyncIterable["models.GalleryImageVersionList"]:
        """List gallery Image Versions in a gallery Image Definition.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param gallery_name: The name of the Shared Image Gallery in which the Image Definition
     resides.
        :type gallery_name: str
        :param gallery_image_name: The name of the Shared Image Gallery Image Definition from which the
     Image Versions are to be listed.
        :type gallery_image_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either GalleryImageVersionList or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.compute.v2019_07_01.models.GalleryImageVersionList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.GalleryImageVersionList"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-07-01"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            if not next_link:
                # Construct URL
                url = self.list_by_gallery_image.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'galleryName': self._serialize.url("gallery_name", gallery_name, 'str'),
                    'galleryImageName': self._serialize.url("gallery_image_name", gallery_image_name, 'str'),
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
            deserialized = self._deserialize('GalleryImageVersionList', pipeline_response)
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
    list_by_gallery_image.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/galleries/{galleryName}/images/{galleryImageName}/versions'}  # type: ignore
