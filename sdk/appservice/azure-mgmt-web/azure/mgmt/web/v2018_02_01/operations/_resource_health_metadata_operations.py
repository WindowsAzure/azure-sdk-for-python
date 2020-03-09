# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, Optional, TypeVar
import warnings

from azure.core.exceptions import map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse

from .. import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class ResourceHealthMetadataOperations(object):
    """ResourceHealthMetadataOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.web.v2018_02_01.models
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

    def list(
        self,
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.ResourceHealthMetadataCollection"
        """List all ResourceHealthMetadata for all sites in the subscription.

        List all ResourceHealthMetadata for all sites in the subscription.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ResourceHealthMetadataCollection or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2018_02_01.models.ResourceHealthMetadataCollection
        :raises: ~azure.mgmt.web.v2018_02_01.models.DefaultErrorResponseException:
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ResourceHealthMetadataCollection"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2018-02-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
            else:
                url = next_link

            # Construct parameters
            query_parameters = {}  # type: Dict[str, Any]
            query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('ResourceHealthMetadataCollection', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise models.DefaultErrorResponseException.from_response(response, self._deserialize)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Web/resourceHealthMetadata'}

    def list_by_resource_group(
        self,
        resource_group_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.ResourceHealthMetadataCollection"
        """List all ResourceHealthMetadata for all sites in the resource group in the subscription.

        List all ResourceHealthMetadata for all sites in the resource group in the subscription.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ResourceHealthMetadataCollection or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2018_02_01.models.ResourceHealthMetadataCollection
        :raises: ~azure.mgmt.web.v2018_02_01.models.DefaultErrorResponseException:
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ResourceHealthMetadataCollection"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2018-02-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_resource_group.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+[^\.]$'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
            else:
                url = next_link

            # Construct parameters
            query_parameters = {}  # type: Dict[str, Any]
            query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('ResourceHealthMetadataCollection', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise models.DefaultErrorResponseException.from_response(response, self._deserialize)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_by_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/resourceHealthMetadata'}

    def list_by_site(
        self,
        resource_group_name,  # type: str
        name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.ResourceHealthMetadataCollection"
        """Gets the category of ResourceHealthMetadata to use for the given site as a collection.

        Gets the category of ResourceHealthMetadata to use for the given site as a collection.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param name: Name of web app.
        :type name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ResourceHealthMetadataCollection or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2018_02_01.models.ResourceHealthMetadataCollection
        :raises: ~azure.mgmt.web.v2018_02_01.models.DefaultErrorResponseException:
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ResourceHealthMetadataCollection"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2018-02-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_site.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+[^\.]$'),
                    'name': self._serialize.url("name", name, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
            else:
                url = next_link

            # Construct parameters
            query_parameters = {}  # type: Dict[str, Any]
            query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('ResourceHealthMetadataCollection', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise models.DefaultErrorResponseException.from_response(response, self._deserialize)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_by_site.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/resourceHealthMetadata'}

    def get_by_site(
        self,
        resource_group_name,  # type: str
        name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.ResourceHealthMetadata"
        """Gets the category of ResourceHealthMetadata to use for the given site.

        Gets the category of ResourceHealthMetadata to use for the given site.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param name: Name of web app.
        :type name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ResourceHealthMetadata or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2018_02_01.models.ResourceHealthMetadata
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ResourceHealthMetadata"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2018-02-01"

        # Construct URL
        url = self.get_by_site.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+[^\.]$'),
            'name': self._serialize.url("name", name, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
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
            raise models.DefaultErrorResponseException.from_response(response, self._deserialize)

        deserialized = self._deserialize('ResourceHealthMetadata', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get_by_site.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/resourceHealthMetadata/default'}

    def list_by_site_slot(
        self,
        resource_group_name,  # type: str
        name,  # type: str
        slot,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.ResourceHealthMetadataCollection"
        """Gets the category of ResourceHealthMetadata to use for the given site as a collection.

        Gets the category of ResourceHealthMetadata to use for the given site as a collection.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param name: Name of web app.
        :type name: str
        :param slot: Name of web app slot. If not specified then will default to production slot.
        :type slot: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ResourceHealthMetadataCollection or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2018_02_01.models.ResourceHealthMetadataCollection
        :raises: ~azure.mgmt.web.v2018_02_01.models.DefaultErrorResponseException:
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ResourceHealthMetadataCollection"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2018-02-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_site_slot.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+[^\.]$'),
                    'name': self._serialize.url("name", name, 'str'),
                    'slot': self._serialize.url("slot", slot, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
            else:
                url = next_link

            # Construct parameters
            query_parameters = {}  # type: Dict[str, Any]
            query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('ResourceHealthMetadataCollection', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise models.DefaultErrorResponseException.from_response(response, self._deserialize)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_by_site_slot.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots/{slot}/resourceHealthMetadata'}

    def get_by_site_slot(
        self,
        resource_group_name,  # type: str
        name,  # type: str
        slot,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.ResourceHealthMetadata"
        """Gets the category of ResourceHealthMetadata to use for the given site.

        Gets the category of ResourceHealthMetadata to use for the given site.

        :param resource_group_name: Name of the resource group to which the resource belongs.
        :type resource_group_name: str
        :param name: Name of web app.
        :type name: str
        :param slot: Name of web app slot. If not specified then will default to production slot.
        :type slot: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ResourceHealthMetadata or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2018_02_01.models.ResourceHealthMetadata
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ResourceHealthMetadata"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2018-02-01"

        # Construct URL
        url = self.get_by_site_slot.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+[^\.]$'),
            'name': self._serialize.url("name", name, 'str'),
            'slot': self._serialize.url("slot", slot, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
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
            raise models.DefaultErrorResponseException.from_response(response, self._deserialize)

        deserialized = self._deserialize('ResourceHealthMetadata', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get_by_site_slot.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/slots/{slot}/resourceHealthMetadata/default'}
