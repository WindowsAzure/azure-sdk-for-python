# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class IndexersOperations(object):
    """IndexersOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.search.documents.indexes.v2020_06_preview.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def reset(
        self,
        indexer_name,  # type: str
        request_options=None,  # type: Optional["_models.RequestOptions"]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Resets the change tracking state associated with an indexer.

        :param indexer_name: The name of the indexer to reset.
        :type indexer_name: str
        :param request_options: Parameter group.
        :type request_options: ~azure.search.documents.indexes.v2020_06_preview.models.RequestOptions
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
        
        _x_ms_client_request_id = None
        if request_options is not None:
            _x_ms_client_request_id = request_options.x_ms_client_request_id
        api_version = "2020-06-30-Preview"
        accept = "application/json"

        # Construct URL
        url = self.reset.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'indexerName': self._serialize.url("indexer_name", indexer_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if _x_ms_client_request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("x_ms_client_request_id", _x_ms_client_request_id, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.SearchError, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    reset.metadata = {'url': '/indexers(\'{indexerName}\')/search.reset'}  # type: ignore

    def run(
        self,
        indexer_name,  # type: str
        request_options=None,  # type: Optional["_models.RequestOptions"]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Runs an indexer on-demand.

        :param indexer_name: The name of the indexer to run.
        :type indexer_name: str
        :param request_options: Parameter group.
        :type request_options: ~azure.search.documents.indexes.v2020_06_preview.models.RequestOptions
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
        
        _x_ms_client_request_id = None
        if request_options is not None:
            _x_ms_client_request_id = request_options.x_ms_client_request_id
        api_version = "2020-06-30-Preview"
        accept = "application/json"

        # Construct URL
        url = self.run.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'indexerName': self._serialize.url("indexer_name", indexer_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if _x_ms_client_request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("x_ms_client_request_id", _x_ms_client_request_id, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.SearchError, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    run.metadata = {'url': '/indexers(\'{indexerName}\')/search.run'}  # type: ignore

    def create_or_update(
        self,
        indexer_name,  # type: str
        indexer,  # type: "_models.SearchIndexer"
        if_match=None,  # type: Optional[str]
        if_none_match=None,  # type: Optional[str]
        request_options=None,  # type: Optional["_models.RequestOptions"]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.SearchIndexer"
        """Creates a new indexer or updates an indexer if it already exists.

        :param indexer_name: The name of the indexer to create or update.
        :type indexer_name: str
        :param indexer: The definition of the indexer to create or update.
        :type indexer: ~azure.search.documents.indexes.v2020_06_preview.models.SearchIndexer
        :param if_match: Defines the If-Match condition. The operation will be performed only if the
         ETag on the server matches this value.
        :type if_match: str
        :param if_none_match: Defines the If-None-Match condition. The operation will be performed only
         if the ETag on the server does not match this value.
        :type if_none_match: str
        :param request_options: Parameter group.
        :type request_options: ~azure.search.documents.indexes.v2020_06_preview.models.RequestOptions
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SearchIndexer, or the result of cls(response)
        :rtype: ~azure.search.documents.indexes.v2020_06_preview.models.SearchIndexer
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SearchIndexer"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        
        _x_ms_client_request_id = None
        if request_options is not None:
            _x_ms_client_request_id = request_options.x_ms_client_request_id
        prefer = "return=representation"
        api_version = "2020-06-30-Preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create_or_update.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'indexerName': self._serialize.url("indexer_name", indexer_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if _x_ms_client_request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("x_ms_client_request_id", _x_ms_client_request_id, 'str')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')
        header_parameters['Prefer'] = self._serialize.header("prefer", prefer, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(indexer, 'SearchIndexer')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.SearchError, response)
            raise HttpResponseError(response=response, model=error)

        if response.status_code == 200:
            deserialized = self._deserialize('SearchIndexer', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('SearchIndexer', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_or_update.metadata = {'url': '/indexers(\'{indexerName}\')'}  # type: ignore

    def delete(
        self,
        indexer_name,  # type: str
        if_match=None,  # type: Optional[str]
        if_none_match=None,  # type: Optional[str]
        request_options=None,  # type: Optional["_models.RequestOptions"]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Deletes an indexer.

        :param indexer_name: The name of the indexer to delete.
        :type indexer_name: str
        :param if_match: Defines the If-Match condition. The operation will be performed only if the
         ETag on the server matches this value.
        :type if_match: str
        :param if_none_match: Defines the If-None-Match condition. The operation will be performed only
         if the ETag on the server does not match this value.
        :type if_none_match: str
        :param request_options: Parameter group.
        :type request_options: ~azure.search.documents.indexes.v2020_06_preview.models.RequestOptions
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
        
        _x_ms_client_request_id = None
        if request_options is not None:
            _x_ms_client_request_id = request_options.x_ms_client_request_id
        api_version = "2020-06-30-Preview"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'indexerName': self._serialize.url("indexer_name", indexer_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if _x_ms_client_request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("x_ms_client_request_id", _x_ms_client_request_id, 'str')
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [204, 404]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.SearchError, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/indexers(\'{indexerName}\')'}  # type: ignore

    def get(
        self,
        indexer_name,  # type: str
        request_options=None,  # type: Optional["_models.RequestOptions"]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.SearchIndexer"
        """Retrieves an indexer definition.

        :param indexer_name: The name of the indexer to retrieve.
        :type indexer_name: str
        :param request_options: Parameter group.
        :type request_options: ~azure.search.documents.indexes.v2020_06_preview.models.RequestOptions
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SearchIndexer, or the result of cls(response)
        :rtype: ~azure.search.documents.indexes.v2020_06_preview.models.SearchIndexer
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SearchIndexer"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        
        _x_ms_client_request_id = None
        if request_options is not None:
            _x_ms_client_request_id = request_options.x_ms_client_request_id
        api_version = "2020-06-30-Preview"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'indexerName': self._serialize.url("indexer_name", indexer_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if _x_ms_client_request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("x_ms_client_request_id", _x_ms_client_request_id, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.SearchError, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('SearchIndexer', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/indexers(\'{indexerName}\')'}  # type: ignore

    def list(
        self,
        select=None,  # type: Optional[str]
        request_options=None,  # type: Optional["_models.RequestOptions"]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.ListIndexersResult"
        """Lists all indexers available for a search service.

        :param select: Selects which top-level properties of the indexers to retrieve. Specified as a
         comma-separated list of JSON property names, or '*' for all properties. The default is all
         properties.
        :type select: str
        :param request_options: Parameter group.
        :type request_options: ~azure.search.documents.indexes.v2020_06_preview.models.RequestOptions
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ListIndexersResult, or the result of cls(response)
        :rtype: ~azure.search.documents.indexes.v2020_06_preview.models.ListIndexersResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ListIndexersResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        
        _x_ms_client_request_id = None
        if request_options is not None:
            _x_ms_client_request_id = request_options.x_ms_client_request_id
        api_version = "2020-06-30-Preview"
        accept = "application/json"

        # Construct URL
        url = self.list.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if select is not None:
            query_parameters['$select'] = self._serialize.query("select", select, 'str')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if _x_ms_client_request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("x_ms_client_request_id", _x_ms_client_request_id, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.SearchError, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('ListIndexersResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    list.metadata = {'url': '/indexers'}  # type: ignore

    def create(
        self,
        indexer,  # type: "_models.SearchIndexer"
        request_options=None,  # type: Optional["_models.RequestOptions"]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.SearchIndexer"
        """Creates a new indexer.

        :param indexer: The definition of the indexer to create.
        :type indexer: ~azure.search.documents.indexes.v2020_06_preview.models.SearchIndexer
        :param request_options: Parameter group.
        :type request_options: ~azure.search.documents.indexes.v2020_06_preview.models.RequestOptions
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SearchIndexer, or the result of cls(response)
        :rtype: ~azure.search.documents.indexes.v2020_06_preview.models.SearchIndexer
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SearchIndexer"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        
        _x_ms_client_request_id = None
        if request_options is not None:
            _x_ms_client_request_id = request_options.x_ms_client_request_id
        api_version = "2020-06-30-Preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if _x_ms_client_request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("x_ms_client_request_id", _x_ms_client_request_id, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(indexer, 'SearchIndexer')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.SearchError, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('SearchIndexer', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create.metadata = {'url': '/indexers'}  # type: ignore

    def get_status(
        self,
        indexer_name,  # type: str
        request_options=None,  # type: Optional["_models.RequestOptions"]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.SearchIndexerStatus"
        """Returns the current status and execution history of an indexer.

        :param indexer_name: The name of the indexer for which to retrieve status.
        :type indexer_name: str
        :param request_options: Parameter group.
        :type request_options: ~azure.search.documents.indexes.v2020_06_preview.models.RequestOptions
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SearchIndexerStatus, or the result of cls(response)
        :rtype: ~azure.search.documents.indexes.v2020_06_preview.models.SearchIndexerStatus
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SearchIndexerStatus"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        
        _x_ms_client_request_id = None
        if request_options is not None:
            _x_ms_client_request_id = request_options.x_ms_client_request_id
        api_version = "2020-06-30-Preview"
        accept = "application/json"

        # Construct URL
        url = self.get_status.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'indexerName': self._serialize.url("indexer_name", indexer_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if _x_ms_client_request_id is not None:
            header_parameters['x-ms-client-request-id'] = self._serialize.header("x_ms_client_request_id", _x_ms_client_request_id, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.SearchError, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('SearchIndexerStatus', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_status.metadata = {'url': '/indexers(\'{indexerName}\')/search.status'}  # type: ignore
