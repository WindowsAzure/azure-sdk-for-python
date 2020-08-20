# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse

from .. import models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class SchemaOperations(object):
    """SchemaOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.schemaregistry._generated.models
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

    def get_by_id(
        self,
        schema_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> str
        """Gets a registered schema by its unique ID.  Azure Schema Registry guarantees that ID is unique within a namespace.

        Get a registered schema by its unique ID reference.

        :param schema_id: References specific schema in registry namespace.
        :type schema_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: str, or the result of cls(response)
        :rtype: str
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[str]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2017-04"  # TODO: manually patch, the default value generated is "2018-01-01-preview"

        # Construct URL
        url = self.get_by_id.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'schema-id': self._serialize.url("schema_id", schema_id, 'str'),
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
            error = self._deserialize('object', response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['Location']=self._deserialize('str', response.headers.get('Location'))
        response_headers['X-Schema-Type']=self._deserialize('str', response.headers.get('X-Schema-Type'))
        response_headers['X-Schema-Id']=self._deserialize('str', response.headers.get('X-Schema-Id'))
        response_headers['X-Schema-Id-Location']=self._deserialize('str', response.headers.get('X-Schema-Id-Location'))
        response_headers['X-Schema-Version']=self._deserialize('int', response.headers.get('X-Schema-Version'))
        deserialized = self._deserialize('str', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    get_by_id.metadata = {'url': '/$schemagroups/getSchemaById/{schema-id}'}  # type: ignore

    def query_id_by_content(
        self,
        group_name,  # type: str
        schema_name,  # type: str
        schema_content,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.SchemaId"
        """Gets the ID referencing an existing schema within the specified schema group, as matched by schema content comparison.

        Get ID for existing schema.

        :param group_name: Schema group under which schema is registered.  Group's serialization type
         should match the serialization type specified in the request.
        :type group_name: str
        :param schema_name: Name of the registered schema.
        :type schema_name: str
        :param schema_content: String representation of the registered schema.
        :type schema_content: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SchemaId, or the result of cls(response)
        :rtype: ~azure.schemaregistry._generated.models.SchemaId
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.SchemaId"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        x_schema_type = "avro"
        api_version = "2017-04"  # TODO: manually patch, the default value generated is "2018-01-01-preview"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self.query_id_by_content.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'group-name': self._serialize.url("group_name", group_name, 'str'),
            'schema-name': self._serialize.url("schema_name", schema_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['X-Schema-Type'] = self._serialize.header("x_schema_type", x_schema_type, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(schema_content, 'str')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize('object', response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['Location']=self._deserialize('str', response.headers.get('Location'))
        response_headers['X-Schema-Type']=self._deserialize('str', response.headers.get('X-Schema-Type'))
        response_headers['X-Schema-Id']=self._deserialize('str', response.headers.get('X-Schema-Id'))
        response_headers['X-Schema-Id-Location']=self._deserialize('str', response.headers.get('X-Schema-Id-Location'))
        response_headers['X-Schema-Version']=self._deserialize('int', response.headers.get('X-Schema-Version'))
        deserialized = self._deserialize('SchemaId', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    query_id_by_content.metadata = {'url': '/$schemagroups/{group-name}/schemas/{schema-name}'}  # type: ignore

    def register(
        self,
        group_name,  # type: str
        schema_name,  # type: str
        schema_content,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.SchemaId"
        """Register new schema. If schema of specified name does not exist in specified group, schema is created at version 1. If schema of specified name exists already in specified group, schema is created at latest version + 1.

        Register new schema.

        :param group_name: Schema group under which schema should be registered.  Group's serialization
         type should match the serialization type specified in the request.
        :type group_name: str
        :param schema_name: Name of schema being registered.
        :type schema_name: str
        :param schema_content: String representation of the schema being registered.
        :type schema_content: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SchemaId, or the result of cls(response)
        :rtype: ~azure.schemaregistry._generated.models.SchemaId
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.SchemaId"]
        error_map = {404: ResourceNotFoundError, 409: ResourceExistsError}
        error_map.update(kwargs.pop('error_map', {}))
        x_schema_type = "avro"
        api_version = "2017-04"  # TODO: manually patch, the default value generated is "2018-01-01-preview"
        content_type = kwargs.pop("content_type", "application/json")

        # Construct URL
        url = self.register.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'group-name': self._serialize.url("group_name", group_name, 'str'),
            'schema-name': self._serialize.url("schema_name", schema_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['X-Schema-Type'] = self._serialize.header("x_schema_type", x_schema_type, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(schema_content, 'str')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)

        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize('object', response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['Location']=self._deserialize('str', response.headers.get('Location'))
        response_headers['X-Schema-Type']=self._deserialize('str', response.headers.get('X-Schema-Type'))
        response_headers['X-Schema-Id']=self._deserialize('str', response.headers.get('X-Schema-Id'))
        response_headers['X-Schema-Id-Location']=self._deserialize('str', response.headers.get('X-Schema-Id-Location'))
        response_headers['X-Schema-Version']=self._deserialize('int', response.headers.get('X-Schema-Version'))
        deserialized = self._deserialize('SchemaId', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    register.metadata = {'url': '/$schemagroups/{group-name}/schemas/{schema-name}'}  # type: ignore
