# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from json import loads as _loads
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpResponse
from azure.farmbeats.core.rest import HttpRequest

from ..rest import oauth_providers as rest_oauth_providers

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, List, Optional, TypeVar, Union

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class OAuthProvidersOperations(object):
    """OAuthProvidersOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def list(
        self,
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable[Any]
        """Returns a paginated list of oauthProvider resources.

        :keyword ids: Ids of the resource.
        :paramtype ids: list[str]
        :keyword names: Names of the resource.
        :paramtype names: list[str]
        :keyword property_filters: Filters on key-value pairs within the Properties object.
         eg. "{testkey} eq {testvalue}".
        :paramtype property_filters: list[str]
        :keyword statuses: Statuses of the resource.
        :paramtype statuses: list[str]
        :keyword min_created_date_time: Minimum creation date of resource (inclusive).
        :paramtype min_created_date_time: ~datetime.datetime
        :keyword max_created_date_time: Maximum creation date of resource (inclusive).
        :paramtype max_created_date_time: ~datetime.datetime
        :keyword min_last_modified_date_time: Minimum last modified date of resource (inclusive).
        :paramtype min_last_modified_date_time: ~datetime.datetime
        :keyword max_last_modified_date_time: Maximum last modified date of resource (inclusive).
        :paramtype max_last_modified_date_time: ~datetime.datetime
        :keyword max_page_size: Maximum number of items needed (inclusive).
         Minimum = 10, Maximum = 1000, Default value = 50.
        :paramtype max_page_size: int
        :keyword skip_token: Skip token for getting next set of results.
        :paramtype skip_token: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either Any or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[Any]
        :raises: ~azure.core.exceptions.HttpResponseError

        Example:
            .. code-block:: python



                # response body for status code(s): 200
                response_body == {
                    "$skipToken": "str (optional)",
                    "nextLink": "str (optional)",
                    "value": [
                        {
                            "apiKey": "str (optional)",
                            "appId": "str (optional)",
                            "appSecret": "str (optional)",
                            "createdDateTime": "datetime (optional)",
                            "description": "str (optional)",
                            "eTag": "str (optional)",
                            "id": "str (optional)",
                            "isProductionApp": "bool (optional). Default value is False",
                            "modifiedDateTime": "datetime (optional)",
                            "name": "str (optional)",
                            "properties": {
                                "str": "object (optional)"
                            }
                        }
                    ]
                }

        """

        ids = kwargs.pop('ids', None)  # type: Optional[List[str]]
        names = kwargs.pop('names', None)  # type: Optional[List[str]]
        property_filters = kwargs.pop('property_filters', None)  # type: Optional[List[str]]
        statuses = kwargs.pop('statuses', None)  # type: Optional[List[str]]
        min_created_date_time = kwargs.pop('min_created_date_time', None)  # type: Optional[datetime.datetime]
        max_created_date_time = kwargs.pop('max_created_date_time', None)  # type: Optional[datetime.datetime]
        min_last_modified_date_time = kwargs.pop('min_last_modified_date_time', None)  # type: Optional[datetime.datetime]
        max_last_modified_date_time = kwargs.pop('max_last_modified_date_time', None)  # type: Optional[datetime.datetime]
        max_page_size = kwargs.pop('max_page_size', 50)  # type: Optional[int]
        skip_token = kwargs.pop('skip_token', None)  # type: Optional[str]
        cls = kwargs.pop('cls', None)  # type: ClsType[Any]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        def prepare_request(next_link=None):
            if not next_link:
                request = rest_oauth_providers.build_list_request(
                    ids=ids,
                    names=names,
                    property_filters=property_filters,
                    statuses=statuses,
                    min_created_date_time=min_created_date_time,
                    max_created_date_time=max_created_date_time,
                    min_last_modified_date_time=min_last_modified_date_time,
                    max_last_modified_date_time=max_last_modified_date_time,
                    max_page_size=max_page_size,
                    skip_token=skip_token,
                    template_url=self.list.metadata['url'],
                    **kwargs
                )._internal_request
                path_format_arguments = {
                    'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                }
                request.url = self._client.format_url(request.url, **path_format_arguments)
                kwargs.pop("content_type", None)
            else:
                request = rest_oauth_providers.build_list_request(
                    ids=ids,
                    names=names,
                    property_filters=property_filters,
                    statuses=statuses,
                    min_created_date_time=min_created_date_time,
                    max_created_date_time=max_created_date_time,
                    min_last_modified_date_time=min_last_modified_date_time,
                    max_last_modified_date_time=max_last_modified_date_time,
                    max_page_size=max_page_size,
                    skip_token=skip_token,
                    template_url=self.list.metadata['url'],
                    **kwargs
                )._internal_request
                path_format_arguments = {
                    'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                }
                request.url = self._client.format_url(request.url, **path_format_arguments)
                kwargs.pop("content_type", None)
                # little hacky, but this code will soon be replaced with code that won't need the hack
                path_format_arguments = {
                    'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                }
                request.method = "GET"
                request.url = self._client.format_url(next_link, **path_format_arguments)
            return request

        def extract_data(pipeline_response):
            deserialized = _loads(pipeline_response.http_response.text())
            list_of_elem = deserialized.get('value', [])
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.get('nextLink', None), iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                if response.status_code not in [200]:
                    map_error(status_code=response.status_code, response=response, error_map=error_map)
                    raise HttpResponseError(response=response)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/oauth/providers'}  # type: ignore

    def get(
        self,
        oauth_provider_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> Optional[Any]
        """Get a specified oauthProvider resource.

        :param oauth_provider_id: ID of the oauthProvider resource.
        :type oauth_provider_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Any, or the result of cls(response)
        :rtype: Any or None
        :raises: ~azure.core.exceptions.HttpResponseError

        Example:
            .. code-block:: python


                # response body for status code(s): 200
                response_body == {
                    "apiKey": "str (optional)",
                    "appId": "str (optional)",
                    "appSecret": "str (optional)",
                    "createdDateTime": "datetime (optional)",
                    "description": "str (optional)",
                    "eTag": "str (optional)",
                    "id": "str (optional)",
                    "isProductionApp": "bool (optional). Default value is False",
                    "modifiedDateTime": "datetime (optional)",
                    "name": "str (optional)",
                    "properties": {
                        "str": "object (optional)"
                    }
                }

        """
        cls = kwargs.pop('cls', None)  # type: ClsType[Optional[Any]]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        request = rest_oauth_providers.build_get_request(
            oauth_provider_id=oauth_provider_id,
            template_url=self.get.metadata['url'],
            **kwargs
        )._internal_request
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)
        kwargs.pop("content_type", None)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 404]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = None
        if response.status_code == 200:
            deserialized = _loads(response.text())

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized

    get.metadata = {'url': '/oauth/providers/{oauthProviderId}'}  # type: ignore

    def create_or_update(
        self,
        oauth_provider_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> Any
        """Creates or updates an oauthProvider resource.

        :param oauth_provider_id: ID of oauthProvider resource.
        :type oauth_provider_id: str
        :keyword oauth_provider: OauthProvider resource payload to create or update.
        :paramtype oauth_provider: Any
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Any, or the result of cls(response)
        :rtype: Any
        :raises: ~azure.core.exceptions.HttpResponseError

        Example:
            .. code-block:: python


                # JSON input template you can fill out and use as your `json` input.
                oauth_provider = {
                    "apiKey": "str (optional)",
                    "appId": "str (optional)",
                    "appSecret": "str (optional)",
                    "createdDateTime": "datetime (optional)",
                    "description": "str (optional)",
                    "eTag": "str (optional)",
                    "id": "str (optional)",
                    "isProductionApp": "bool (optional). Default value is False",
                    "modifiedDateTime": "datetime (optional)",
                    "name": "str (optional)",
                    "properties": {
                        "str": "object (optional)"
                    }
                }


                # response body for status code(s): 200, 201
                response_body == {
                    "apiKey": "str (optional)",
                    "appId": "str (optional)",
                    "appSecret": "str (optional)",
                    "createdDateTime": "datetime (optional)",
                    "description": "str (optional)",
                    "eTag": "str (optional)",
                    "id": "str (optional)",
                    "isProductionApp": "bool (optional). Default value is False",
                    "modifiedDateTime": "datetime (optional)",
                    "name": "str (optional)",
                    "properties": {
                        "str": "object (optional)"
                    }
                }

        """
        cls = kwargs.pop('cls', None)  # type: ClsType[Any]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        oauth_provider = kwargs.pop('oauth_provider', None)  # type: Any

        content_type = kwargs.pop("content_type", "application/merge-patch+json")
        if oauth_provider is not None:
            json = self._serialize.body(oauth_provider, 'object')
        else:
            json = None


        request = rest_oauth_providers.build_create_or_update_request(
            oauth_provider_id=oauth_provider_id,
            json=json,
            content_type=content_type,
            template_url=self.create_or_update.metadata['url'],
            **kwargs
        )._internal_request
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)
        kwargs.pop("content_type", None)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if response.status_code == 200:
            deserialized = _loads(response.text())

        if response.status_code == 201:
            deserialized = _loads(response.text())

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized

    create_or_update.metadata = {'url': '/oauth/providers/{oauthProviderId}'}  # type: ignore

    def delete(
        self,
        oauth_provider_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Deletes an specified oauthProvider resource.

        :param oauth_provider_id: ID of oauthProvider.
        :type oauth_provider_id: str
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

        request = rest_oauth_providers.build_delete_request(
            oauth_provider_id=oauth_provider_id,
            template_url=self.delete.metadata['url'],
            **kwargs
        )._internal_request
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)
        kwargs.pop("content_type", None)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/oauth/providers/{oauthProviderId}'}  # type: ignore
