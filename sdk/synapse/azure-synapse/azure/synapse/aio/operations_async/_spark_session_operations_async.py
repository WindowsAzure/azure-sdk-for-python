# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, Optional, TypeVar
import warnings

from azure.core.exceptions import HttpResponseError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest

from ... import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class SparkSessionOperations:
    """SparkSessionOperations async operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.synapse.models
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

    async def list(
        self,
        workspace_name: str,
        spark_pool_name: str,
        from_parameter: Optional[int] = None,
        size: Optional[int] = None,
        detailed: Optional[bool] = None,
        **kwargs
    ) -> "models.ExtendedLivyListSessionResponse":
        """List all spark sessions which are running under a particular spark pool.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param from_parameter: Optional param specifying which index the list should begin from.
        :type from_parameter: int
        :param size: Optional param specifying the size of the returned list.
                     By default it is 20 and that is the maximum.
        :type size: int
        :param detailed: Optional query param specifying whether detailed response is returned beyond
         plain livy.
        :type detailed: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ExtendedLivyListSessionResponse or the result of cls(response)
        :rtype: ~azure.synapse.models.ExtendedLivyListSessionResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType["models.ExtendedLivyListSessionResponse"] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.list.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}
        if from_parameter is not None:
            query_parameters['from'] = self._serialize.query("from_parameter", from_parameter, 'int')
        if size is not None:
            query_parameters['size'] = self._serialize.query("size", size, 'int')
        if detailed is not None:
            query_parameters['detailed'] = self._serialize.query("detailed", detailed, 'bool')

        # Construct headers
        header_parameters: Dict[str, Any] = {}
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('ExtendedLivyListSessionResponse', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    list.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions'}

    async def create(
        self,
        workspace_name: str,
        spark_pool_name: str,
        livy_request: "models.ExtendedLivySessionRequest",
        detailed: Optional[bool] = None,
        **kwargs
    ) -> "models.ExtendedLivySessionResponse":
        """Create new spark session.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param livy_request: Livy compatible batch job request payload.
        :type livy_request: ~azure.synapse.models.ExtendedLivySessionRequest
        :param detailed: Optional query param specifying whether detailed response is returned beyond
         plain livy.
        :type detailed: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ExtendedLivySessionResponse or the result of cls(response)
        :rtype: ~azure.synapse.models.ExtendedLivySessionResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType["models.ExtendedLivySessionResponse"] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}
        if detailed is not None:
            query_parameters['detailed'] = self._serialize.query("detailed", detailed, 'bool')

        # Construct headers
        header_parameters: Dict[str, Any] = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json'

        # Construct body
        body_content = self._serialize.body(livy_request, 'ExtendedLivySessionRequest')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('ExtendedLivySessionResponse', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    create.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions'}

    async def get(
        self,
        workspace_name: str,
        spark_pool_name: str,
        session_id: int,
        detailed: Optional[bool] = None,
        **kwargs
    ) -> "models.ExtendedLivySessionResponse":
        """Gets a single spark session.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param session_id: Identifier for the session.
        :type session_id: int
        :param detailed: Optional query param specifying whether detailed response is returned beyond
         plain livy.
        :type detailed: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ExtendedLivySessionResponse or the result of cls(response)
        :rtype: ~azure.synapse.models.ExtendedLivySessionResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType["models.ExtendedLivySessionResponse"] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
            'sessionId': self._serialize.url("session_id", session_id, 'int'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}
        if detailed is not None:
            query_parameters['detailed'] = self._serialize.query("detailed", detailed, 'bool')

        # Construct headers
        header_parameters: Dict[str, Any] = {}
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('ExtendedLivySessionResponse', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions/{sessionId}'}

    async def delete(
        self,
        workspace_name: str,
        spark_pool_name: str,
        session_id: int,
        **kwargs
    ) -> None:
        """Cancels a running spark session.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param session_id: Identifier for the session.
        :type session_id: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType[None] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
            'sessionId': self._serialize.url("session_id", session_id, 'int'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}

        # Construct headers
        header_parameters: Dict[str, Any] = {}

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if cls:
          return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions/{sessionId}'}

    async def reset_timeout(
        self,
        workspace_name: str,
        spark_pool_name: str,
        session_id: int,
        **kwargs
    ) -> None:
        """Sends a keep alive call to the current session to reset the session timeout.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param session_id: Identifier for the session.
        :type session_id: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType[None] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.reset_timeout.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
            'sessionId': self._serialize.url("session_id", session_id, 'int'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}

        # Construct headers
        header_parameters: Dict[str, Any] = {}

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        if cls:
          return cls(pipeline_response, None, {})

    reset_timeout.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions/{sessionId}/reset-timeout'}

    async def list_statements(
        self,
        workspace_name: str,
        spark_pool_name: str,
        session_id: int,
        **kwargs
    ) -> "models.LivyStatementsResponseBody":
        """Gets a list of statements within a spark session.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param session_id: Identifier for the session.
        :type session_id: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: LivyStatementsResponseBody or the result of cls(response)
        :rtype: ~azure.synapse.models.LivyStatementsResponseBody
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType["models.LivyStatementsResponseBody"] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.list_statements.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
            'sessionId': self._serialize.url("session_id", session_id, 'int'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}

        # Construct headers
        header_parameters: Dict[str, Any] = {}
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('LivyStatementsResponseBody', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    list_statements.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions/{sessionId}/statements'}

    async def create_statement(
        self,
        workspace_name: str,
        spark_pool_name: str,
        session_id: int,
        livy_request: "models.LivyStatementRequestBody",
        **kwargs
    ) -> "models.LivyStatementResponseBody":
        """Create statement within a spark session.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param session_id: Identifier for the session.
        :type session_id: int
        :param livy_request: Livy compatible batch job request payload.
        :type livy_request: ~azure.synapse.models.LivyStatementRequestBody
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: LivyStatementResponseBody or the result of cls(response)
        :rtype: ~azure.synapse.models.LivyStatementResponseBody
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType["models.LivyStatementResponseBody"] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.create_statement.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
            'sessionId': self._serialize.url("session_id", session_id, 'int'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}

        # Construct headers
        header_parameters: Dict[str, Any] = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json'

        # Construct body
        body_content = self._serialize.body(livy_request, 'LivyStatementRequestBody')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('LivyStatementResponseBody', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    create_statement.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions/{sessionId}/statements'}

    async def get_statement(
        self,
        workspace_name: str,
        spark_pool_name: str,
        session_id: int,
        statement_id: int,
        **kwargs
    ) -> "models.LivyStatementResponseBody":
        """Gets a single statement within a spark session.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param session_id: Identifier for the session.
        :type session_id: int
        :param statement_id: Identifier for the statement.
        :type statement_id: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: LivyStatementResponseBody or the result of cls(response)
        :rtype: ~azure.synapse.models.LivyStatementResponseBody
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType["models.LivyStatementResponseBody"] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.get_statement.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
            'sessionId': self._serialize.url("session_id", session_id, 'int'),
            'statementId': self._serialize.url("statement_id", statement_id, 'int'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}

        # Construct headers
        header_parameters: Dict[str, Any] = {}
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('LivyStatementResponseBody', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    get_statement.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions/{sessionId}/statements/{statementId}'}

    async def delete_statement(
        self,
        workspace_name: str,
        spark_pool_name: str,
        session_id: int,
        statement_id: int,
        **kwargs
    ) -> "models.LivyStatementCancellationResponse":
        """Kill a statement within a session.

        :param workspace_name: The name of the workspace to execute operations on.
        :type workspace_name: str
        :param spark_pool_name: Name of the spark pool. "ondemand" targets the ondemand pool.
        :type spark_pool_name: str
        :param session_id: Identifier for the session.
        :type session_id: int
        :param statement_id: Identifier for the statement.
        :type statement_id: int
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: LivyStatementCancellationResponse or the result of cls(response)
        :rtype: ~azure.synapse.models.LivyStatementCancellationResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls: ClsType["models.LivyStatementCancellationResponse"] = kwargs.pop('cls', None)
        error_map = kwargs.pop('error_map', {})

        # Construct URL
        url = self.delete_statement.metadata['url']
        path_format_arguments = {
            'workspaceName': self._serialize.url("workspace_name", workspace_name, 'str', skip_quote=True),
            'SynapseDnsSuffix': self._serialize.url("self._config.synapse_dns_suffix", self._config.synapse_dns_suffix, 'str', skip_quote=True),
            'livyApiVersion': self._serialize.url("self._config.livy_api_version", self._config.livy_api_version, 'str', skip_quote=True),
            'sparkPoolName': self._serialize.url("spark_pool_name", spark_pool_name, 'str'),
            'sessionId': self._serialize.url("session_id", session_id, 'int'),
            'statementId': self._serialize.url("statement_id", statement_id, 'int'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters: Dict[str, Any] = {}

        # Construct headers
        header_parameters: Dict[str, Any] = {}
        header_parameters['Accept'] = 'application/json'

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('LivyStatementCancellationResponse', pipeline_response)

        if cls:
          return cls(pipeline_response, deserialized, {})

        return deserialized
    delete_statement.metadata = {'url': '/livyApi/versions/{livyApiVersion}/sparkPools/{sparkPoolName}/sessions/{sessionId}/statements/{statementId}/cancel'}
