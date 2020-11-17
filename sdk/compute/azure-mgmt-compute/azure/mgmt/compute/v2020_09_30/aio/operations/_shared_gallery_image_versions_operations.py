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
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class SharedGalleryImageVersionsOperations:
    """SharedGalleryImageVersionsOperations async operations.

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

    def list(
        self,
        location: str,
        gallery_unique_name: str,
        gallery_image_name: str,
        shared_to: Optional[Union[str, "_models.SharedToValues"]] = None,
        **kwargs
    ) -> AsyncIterable["_models.SharedGalleryImageVersionList"]:
        """List shared gallery image versions by subscription id or tenant id.

        :param location: Resource location.
        :type location: str
        :param gallery_unique_name: The unique name of the Shared Gallery.
        :type gallery_unique_name: str
        :param gallery_image_name: The name of the Shared Gallery Image Definition from which the Image
         Versions are to be listed.
        :type gallery_image_name: str
        :param shared_to: The query parameter to decide what shared galleries to fetch when doing
         listing operations.
        :type shared_to: str or ~azure.mgmt.compute.v2020_09_30.models.SharedToValues
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either SharedGalleryImageVersionList or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.compute.v2020_09_30.models.SharedGalleryImageVersionList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SharedGalleryImageVersionList"]
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
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                    'location': self._serialize.url("location", location, 'str'),
                    'galleryUniqueName': self._serialize.url("gallery_unique_name", gallery_unique_name, 'str'),
                    'galleryImageName': self._serialize.url("gallery_image_name", gallery_image_name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if shared_to is not None:
                    query_parameters['sharedTo'] = self._serialize.query("shared_to", shared_to, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('SharedGalleryImageVersionList', pipeline_response)
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
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/sharedGalleries/{galleryUniqueName}/images/{galleryImageName}/versions'}  # type: ignore

    async def get(
        self,
        location: str,
        gallery_unique_name: str,
        gallery_image_name: str,
        gallery_image_version_name: str,
        **kwargs
    ) -> "_models.SharedGalleryImageVersion":
        """Get a shared gallery image version by subscription id or tenant id.

        :param location: Resource location.
        :type location: str
        :param gallery_unique_name: The unique name of the Shared Gallery.
        :type gallery_unique_name: str
        :param gallery_image_name: The name of the Shared Gallery Image Definition from which the Image
         Versions are to be listed.
        :type gallery_image_name: str
        :param gallery_image_version_name: The name of the gallery image version to be created. Needs
         to follow semantic version name pattern: The allowed characters are digit and period. Digits
         must be within the range of a 32-bit integer. Format:
         :code:`<MajorVersion>`.:code:`<MinorVersion>`.:code:`<Patch>`.
        :type gallery_image_version_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SharedGalleryImageVersion, or the result of cls(response)
        :rtype: ~azure.mgmt.compute.v2020_09_30.models.SharedGalleryImageVersion
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SharedGalleryImageVersion"]
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
            'location': self._serialize.url("location", location, 'str'),
            'galleryUniqueName': self._serialize.url("gallery_unique_name", gallery_unique_name, 'str'),
            'galleryImageName': self._serialize.url("gallery_image_name", gallery_image_name, 'str'),
            'galleryImageVersionName': self._serialize.url("gallery_image_version_name", gallery_image_version_name, 'str'),
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

        deserialized = self._deserialize('SharedGalleryImageVersion', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{location}/sharedGalleries/{galleryUniqueName}/images/{galleryImageName}/versions/{galleryImageVersionName}'}  # type: ignore
