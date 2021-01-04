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

class ArtifactsOperations:
    """ArtifactsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.devtestlabs.models
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
        resource_group_name: str,
        lab_name: str,
        artifact_source_name: str,
        expand: Optional[str] = None,
        filter: Optional[str] = None,
        top: Optional[int] = None,
        orderby: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["_models.ArtifactList"]:
        """List artifacts in a given artifact source.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param artifact_source_name: The name of the artifact source.
        :type artifact_source_name: str
        :param expand: Specify the $expand query. Example: 'properties($select=title)'.
        :type expand: str
        :param filter: The filter to apply to the operation. Example: '$filter=contains(name,'myName').
        :type filter: str
        :param top: The maximum number of resources to return from the operation. Example: '$top=10'.
        :type top: int
        :param orderby: The ordering expression for the results, using OData notation. Example:
         '$orderby=name desc'.
        :type orderby: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either ArtifactList or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.devtestlabs.models.ArtifactList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ArtifactList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-09-15"
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
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'labName': self._serialize.url("lab_name", lab_name, 'str'),
                    'artifactSourceName': self._serialize.url("artifact_source_name", artifact_source_name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if expand is not None:
                    query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                if orderby is not None:
                    query_parameters['$orderby'] = self._serialize.query("orderby", orderby, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('ArtifactList', pipeline_response)
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
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/artifactsources/{artifactSourceName}/artifacts'}  # type: ignore

    async def get(
        self,
        resource_group_name: str,
        lab_name: str,
        artifact_source_name: str,
        name: str,
        expand: Optional[str] = None,
        **kwargs
    ) -> "_models.Artifact":
        """Get artifact.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param artifact_source_name: The name of the artifact source.
        :type artifact_source_name: str
        :param name: The name of the artifact.
        :type name: str
        :param expand: Specify the $expand query. Example: 'properties($select=title)'.
        :type expand: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Artifact, or the result of cls(response)
        :rtype: ~azure.mgmt.devtestlabs.models.Artifact
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Artifact"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-09-15"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'labName': self._serialize.url("lab_name", lab_name, 'str'),
            'artifactSourceName': self._serialize.url("artifact_source_name", artifact_source_name, 'str'),
            'name': self._serialize.url("name", name, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if expand is not None:
            query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
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

        deserialized = self._deserialize('Artifact', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/artifactsources/{artifactSourceName}/artifacts/{name}'}  # type: ignore

    async def generate_arm_template(
        self,
        resource_group_name: str,
        lab_name: str,
        artifact_source_name: str,
        name: str,
        generate_arm_template_request: "_models.GenerateArmTemplateRequest",
        **kwargs
    ) -> "_models.ArmTemplateInfo":
        """Generates an ARM template for the given artifact, uploads the required files to a storage
        account, and validates the generated artifact.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param artifact_source_name: The name of the artifact source.
        :type artifact_source_name: str
        :param name: The name of the artifact.
        :type name: str
        :param generate_arm_template_request: Parameters for generating an ARM template for deploying
         artifacts.
        :type generate_arm_template_request: ~azure.mgmt.devtestlabs.models.GenerateArmTemplateRequest
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ArmTemplateInfo, or the result of cls(response)
        :rtype: ~azure.mgmt.devtestlabs.models.ArmTemplateInfo
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.ArmTemplateInfo"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2018-09-15"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.generate_arm_template.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'labName': self._serialize.url("lab_name", lab_name, 'str'),
            'artifactSourceName': self._serialize.url("artifact_source_name", artifact_source_name, 'str'),
            'name': self._serialize.url("name", name, 'str'),
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
        body_content = self._serialize.body(generate_arm_template_request, 'GenerateArmTemplateRequest')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('ArmTemplateInfo', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    generate_arm_template.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/artifactsources/{artifactSourceName}/artifacts/{name}/generateArmTemplate'}  # type: ignore
