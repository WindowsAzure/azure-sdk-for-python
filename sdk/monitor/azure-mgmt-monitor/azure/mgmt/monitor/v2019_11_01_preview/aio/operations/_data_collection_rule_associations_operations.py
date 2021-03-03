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

class DataCollectionRuleAssociationsOperations:
    """DataCollectionRuleAssociationsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~$(python-base-namespace).v2019_11_01_preview.models
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

    def list_by_resource(
        self,
        resource_uri: str,
        **kwargs
    ) -> AsyncIterable["_models.DataCollectionRuleAssociationProxyOnlyResourceListResult"]:
        """Lists associations for the specified resource.

        Lists associations for the specified resource.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DataCollectionRuleAssociationProxyOnlyResourceListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~$(python-base-namespace).v2019_11_01_preview.models.DataCollectionRuleAssociationProxyOnlyResourceListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataCollectionRuleAssociationProxyOnlyResourceListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-11-01-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_resource.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True, min_length=1),
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
            deserialized = self._deserialize('DataCollectionRuleAssociationProxyOnlyResourceListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_resource.metadata = {'url': '/{resourceUri}/providers/Microsoft.Insights/dataCollectionRuleAssociations'}  # type: ignore

    def list_by_rule(
        self,
        resource_group_name: str,
        data_collection_rule_name: str,
        **kwargs
    ) -> AsyncIterable["_models.DataCollectionRuleAssociationProxyOnlyResourceListResult"]:
        """Lists associations for the specified data collection rule.

        Lists associations for the specified data collection rule.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param data_collection_rule_name: The name of the data collection rule. The name is case
         insensitive.
        :type data_collection_rule_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either DataCollectionRuleAssociationProxyOnlyResourceListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~$(python-base-namespace).v2019_11_01_preview.models.DataCollectionRuleAssociationProxyOnlyResourceListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataCollectionRuleAssociationProxyOnlyResourceListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-11-01-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_rule.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'dataCollectionRuleName': self._serialize.url("data_collection_rule_name", data_collection_rule_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
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
            deserialized = self._deserialize('DataCollectionRuleAssociationProxyOnlyResourceListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_rule.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Insights/dataCollectionRules/{dataCollectionRuleName}/associations'}  # type: ignore

    async def get(
        self,
        resource_uri: str,
        association_name: str,
        **kwargs
    ) -> "_models.DataCollectionRuleAssociationProxyOnlyResource":
        """Returns the specified association.

        Returns the specified association.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :param association_name: The name of the association.
        :type association_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DataCollectionRuleAssociationProxyOnlyResource, or the result of cls(response)
        :rtype: ~$(python-base-namespace).v2019_11_01_preview.models.DataCollectionRuleAssociationProxyOnlyResource
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataCollectionRuleAssociationProxyOnlyResource"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-11-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True, min_length=1),
            'associationName': self._serialize.url("association_name", association_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
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
            error = self._deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('DataCollectionRuleAssociationProxyOnlyResource', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/{resourceUri}/providers/Microsoft.Insights/dataCollectionRuleAssociations/{associationName}'}  # type: ignore

    async def create(
        self,
        resource_uri: str,
        association_name: str,
        body: Optional["_models.DataCollectionRuleAssociationProxyOnlyResource"] = None,
        **kwargs
    ) -> "_models.DataCollectionRuleAssociationProxyOnlyResource":
        """Creates or updates an association.

        Creates or updates an association.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :param association_name: The name of the association.
        :type association_name: str
        :param body: The payload.
        :type body: ~$(python-base-namespace).v2019_11_01_preview.models.DataCollectionRuleAssociationProxyOnlyResource
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: DataCollectionRuleAssociationProxyOnlyResource, or the result of cls(response)
        :rtype: ~$(python-base-namespace).v2019_11_01_preview.models.DataCollectionRuleAssociationProxyOnlyResource
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.DataCollectionRuleAssociationProxyOnlyResource"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-11-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True, min_length=1),
            'associationName': self._serialize.url("association_name", association_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
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
            body_content = self._serialize.body(body, 'DataCollectionRuleAssociationProxyOnlyResource')
        else:
            body_content = None
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('DataCollectionRuleAssociationProxyOnlyResource', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('DataCollectionRuleAssociationProxyOnlyResource', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create.metadata = {'url': '/{resourceUri}/providers/Microsoft.Insights/dataCollectionRuleAssociations/{associationName}'}  # type: ignore

    async def delete(
        self,
        resource_uri: str,
        association_name: str,
        **kwargs
    ) -> None:
        """Deletes an association.

        Deletes an association.

        :param resource_uri: The identifier of the resource.
        :type resource_uri: str
        :param association_name: The name of the association.
        :type association_name: str
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
        api_version = "2019-11-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceUri': self._serialize.url("resource_uri", resource_uri, 'str', skip_quote=True, min_length=1),
            'associationName': self._serialize.url("association_name", association_name, 'str', max_length=64, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/{resourceUri}/providers/Microsoft.Insights/dataCollectionRuleAssociations/{associationName}'}  # type: ignore
