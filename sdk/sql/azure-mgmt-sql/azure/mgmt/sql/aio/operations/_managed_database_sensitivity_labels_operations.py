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

from ... import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class ManagedDatabaseSensitivityLabelsOperations:
    """ManagedDatabaseSensitivityLabelsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.sql.models
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

    async def get(
        self,
        resource_group_name: str,
        managed_instance_name: str,
        database_name: str,
        schema_name: str,
        table_name: str,
        column_name: str,
        sensitivity_label_source: Union[str, "models.SensitivityLabelSource"],
        **kwargs
    ) -> "models.SensitivityLabel":
        """Gets the sensitivity label of a given column.

        :param resource_group_name: The name of the resource group that contains the resource. You can
         obtain this value from the Azure Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param schema_name: The name of the schema.
        :type schema_name: str
        :param table_name: The name of the table.
        :type table_name: str
        :param column_name: The name of the column.
        :type column_name: str
        :param sensitivity_label_source: The source of the sensitivity label.
        :type sensitivity_label_source: str or ~azure.mgmt.sql.models.SensitivityLabelSource
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SensitivityLabel, or the result of cls(response)
        :rtype: ~azure.mgmt.sql.models.SensitivityLabel
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.SensitivityLabel"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-06-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'schemaName': self._serialize.url("schema_name", schema_name, 'str'),
            'tableName': self._serialize.url("table_name", table_name, 'str'),
            'columnName': self._serialize.url("column_name", column_name, 'str'),
            'sensitivityLabelSource': self._serialize.url("sensitivity_label_source", sensitivity_label_source, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
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

        deserialized = self._deserialize('SensitivityLabel', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}/schemas/{schemaName}/tables/{tableName}/columns/{columnName}/sensitivityLabels/{sensitivityLabelSource}'}  # type: ignore

    async def create_or_update(
        self,
        resource_group_name: str,
        managed_instance_name: str,
        database_name: str,
        schema_name: str,
        table_name: str,
        column_name: str,
        parameters: "models.SensitivityLabel",
        **kwargs
    ) -> "models.SensitivityLabel":
        """Creates or updates the sensitivity label of a given column.

        :param resource_group_name: The name of the resource group that contains the resource. You can
         obtain this value from the Azure Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param schema_name: The name of the schema.
        :type schema_name: str
        :param table_name: The name of the table.
        :type table_name: str
        :param column_name: The name of the column.
        :type column_name: str
        :param parameters: The column sensitivity label resource.
        :type parameters: ~azure.mgmt.sql.models.SensitivityLabel
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SensitivityLabel, or the result of cls(response)
        :rtype: ~azure.mgmt.sql.models.SensitivityLabel
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.SensitivityLabel"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        sensitivity_label_source = "current"
        api_version = "2018-06-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create_or_update.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'schemaName': self._serialize.url("schema_name", schema_name, 'str'),
            'tableName': self._serialize.url("table_name", table_name, 'str'),
            'columnName': self._serialize.url("column_name", column_name, 'str'),
            'sensitivityLabelSource': self._serialize.url("sensitivity_label_source", sensitivity_label_source, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
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
        body_content = self._serialize.body(parameters, 'SensitivityLabel')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('SensitivityLabel', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('SensitivityLabel', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}/schemas/{schemaName}/tables/{tableName}/columns/{columnName}/sensitivityLabels/{sensitivityLabelSource}'}  # type: ignore

    async def delete(
        self,
        resource_group_name: str,
        managed_instance_name: str,
        database_name: str,
        schema_name: str,
        table_name: str,
        column_name: str,
        **kwargs
    ) -> None:
        """Deletes the sensitivity label of a given column.

        :param resource_group_name: The name of the resource group that contains the resource. You can
         obtain this value from the Azure Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param schema_name: The name of the schema.
        :type schema_name: str
        :param table_name: The name of the table.
        :type table_name: str
        :param column_name: The name of the column.
        :type column_name: str
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
        sensitivity_label_source = "current"
        api_version = "2018-06-01-preview"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'schemaName': self._serialize.url("schema_name", schema_name, 'str'),
            'tableName': self._serialize.url("table_name", table_name, 'str'),
            'columnName': self._serialize.url("column_name", column_name, 'str'),
            'sensitivityLabelSource': self._serialize.url("sensitivity_label_source", sensitivity_label_source, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
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

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}/schemas/{schemaName}/tables/{tableName}/columns/{columnName}/sensitivityLabels/{sensitivityLabelSource}'}  # type: ignore

    async def disable_recommendation(
        self,
        resource_group_name: str,
        managed_instance_name: str,
        database_name: str,
        schema_name: str,
        table_name: str,
        column_name: str,
        **kwargs
    ) -> None:
        """Disables sensitivity recommendations on a given column.

        :param resource_group_name: The name of the resource group that contains the resource. You can
         obtain this value from the Azure Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param schema_name: The name of the schema.
        :type schema_name: str
        :param table_name: The name of the table.
        :type table_name: str
        :param column_name: The name of the column.
        :type column_name: str
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
        sensitivity_label_source = "recommended"
        api_version = "2018-06-01-preview"

        # Construct URL
        url = self.disable_recommendation.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'schemaName': self._serialize.url("schema_name", schema_name, 'str'),
            'tableName': self._serialize.url("table_name", table_name, 'str'),
            'columnName': self._serialize.url("column_name", column_name, 'str'),
            'sensitivityLabelSource': self._serialize.url("sensitivity_label_source", sensitivity_label_source, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    disable_recommendation.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}/schemas/{schemaName}/tables/{tableName}/columns/{columnName}/sensitivityLabels/{sensitivityLabelSource}/disable'}  # type: ignore

    async def enable_recommendation(
        self,
        resource_group_name: str,
        managed_instance_name: str,
        database_name: str,
        schema_name: str,
        table_name: str,
        column_name: str,
        **kwargs
    ) -> None:
        """Enables sensitivity recommendations on a given column (recommendations are enabled by default
        on all columns).

        :param resource_group_name: The name of the resource group that contains the resource. You can
         obtain this value from the Azure Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param schema_name: The name of the schema.
        :type schema_name: str
        :param table_name: The name of the table.
        :type table_name: str
        :param column_name: The name of the column.
        :type column_name: str
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
        sensitivity_label_source = "recommended"
        api_version = "2018-06-01-preview"

        # Construct URL
        url = self.enable_recommendation.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
            'databaseName': self._serialize.url("database_name", database_name, 'str'),
            'schemaName': self._serialize.url("schema_name", schema_name, 'str'),
            'tableName': self._serialize.url("table_name", table_name, 'str'),
            'columnName': self._serialize.url("column_name", column_name, 'str'),
            'sensitivityLabelSource': self._serialize.url("sensitivity_label_source", sensitivity_label_source, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    enable_recommendation.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}/schemas/{schemaName}/tables/{tableName}/columns/{columnName}/sensitivityLabels/{sensitivityLabelSource}/enable'}  # type: ignore

    def list_current_by_database(
        self,
        resource_group_name: str,
        managed_instance_name: str,
        database_name: str,
        filter: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["models.SensitivityLabelListResult"]:
        """Gets the sensitivity labels of a given database.

        :param resource_group_name: The name of the resource group that contains the resource. You can
         obtain this value from the Azure Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param filter: An OData filter expression that filters elements in the collection.
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either SensitivityLabelListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.sql.models.SensitivityLabelListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.SensitivityLabelListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-06-01-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_current_by_database.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
                    'databaseName': self._serialize.url("database_name", database_name, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('SensitivityLabelListResult', pipeline_response)
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
    list_current_by_database.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}/currentSensitivityLabels'}  # type: ignore

    def list_recommended_by_database(
        self,
        resource_group_name: str,
        managed_instance_name: str,
        database_name: str,
        include_disabled_recommendations: Optional[bool] = None,
        skip_token: Optional[str] = None,
        filter: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["models.SensitivityLabelListResult"]:
        """Gets the sensitivity labels of a given database.

        :param resource_group_name: The name of the resource group that contains the resource. You can
         obtain this value from the Azure Resource Manager API or the portal.
        :type resource_group_name: str
        :param managed_instance_name: The name of the managed instance.
        :type managed_instance_name: str
        :param database_name: The name of the database.
        :type database_name: str
        :param include_disabled_recommendations: Specifies whether to include disabled recommendations
         or not.
        :type include_disabled_recommendations: bool
        :param skip_token:
        :type skip_token: str
        :param filter: An OData filter expression that filters elements in the collection.
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either SensitivityLabelListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.sql.models.SensitivityLabelListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.SensitivityLabelListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-06-01-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_recommended_by_database.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'managedInstanceName': self._serialize.url("managed_instance_name", managed_instance_name, 'str'),
                    'databaseName': self._serialize.url("database_name", database_name, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if include_disabled_recommendations is not None:
                    query_parameters['includeDisabledRecommendations'] = self._serialize.query("include_disabled_recommendations", include_disabled_recommendations, 'bool')
                if skip_token is not None:
                    query_parameters['$skipToken'] = self._serialize.query("skip_token", skip_token, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('SensitivityLabelListResult', pipeline_response)
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
    list_recommended_by_database.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{managedInstanceName}/databases/{databaseName}/recommendedSensitivityLabels'}  # type: ignore
