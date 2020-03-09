# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMError

from .. import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class ProviderOperations(object):
    """ProviderOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.web.v2016_03_01.models
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

    def get_available_stacks(
        self,
        os_type_selected=None,  # type: Optional[Union[str, "models.Enum0"]]
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.ApplicationStackCollection"
        """Get available application frameworks and their versions.

        Get available application frameworks and their versions.

        :param os_type_selected:
        :type os_type_selected: str or ~azure.mgmt.web.v2016_03_01.models.Enum0
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ApplicationStackCollection or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2016_03_01.models.ApplicationStackCollection
        :raises: ~azure.mgmt.core.ARMError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ApplicationStackCollection"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2016-03-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.get_available_stacks.metadata['url']
            else:
                url = next_link

            # Construct parameters
            query_parameters = {}  # type: Dict[str, Any]
            if os_type_selected is not None:
                query_parameters['osTypeSelected'] = self._serialize.query("os_type_selected", os_type_selected, 'str')
            query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('ApplicationStackCollection', pipeline_response)
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
                raise ARMError(response=response)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    get_available_stacks.metadata = {'url': '/providers/Microsoft.Web/availableStacks'}

    def list_operations(
        self,
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.CsmOperationCollection"
        """Gets all available operations for the Microsoft.Web resource provider. Also exposes resource metric definitions.

        Gets all available operations for the Microsoft.Web resource provider. Also exposes resource
    metric definitions.

        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CsmOperationCollection or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2016_03_01.models.CsmOperationCollection
        :raises: ~azure.mgmt.core.ARMError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.CsmOperationCollection"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2016-03-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_operations.metadata['url']
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
            deserialized = self._deserialize('CsmOperationCollection', pipeline_response)
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
                raise ARMError(response=response)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_operations.metadata = {'url': '/providers/Microsoft.Web/operations'}

    def get_available_stacks_on_prem(
        self,
        os_type_selected=None,  # type: Optional[Union[str, "models.Enum1"]]
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.ApplicationStackCollection"
        """Get available application frameworks and their versions.

        Get available application frameworks and their versions.

        :param os_type_selected:
        :type os_type_selected: str or ~azure.mgmt.web.v2016_03_01.models.Enum1
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: ApplicationStackCollection or the result of cls(response)
        :rtype: ~azure.mgmt.web.v2016_03_01.models.ApplicationStackCollection
        :raises: ~azure.mgmt.core.ARMError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ApplicationStackCollection"]
        error_map = kwargs.pop('error_map', {})
        api_version = "2016-03-01"

        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.get_available_stacks_on_prem.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
            else:
                url = next_link

            # Construct parameters
            query_parameters = {}  # type: Dict[str, Any]
            if os_type_selected is not None:
                query_parameters['osTypeSelected'] = self._serialize.query("os_type_selected", os_type_selected, 'str')
            query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = 'application/json'

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('ApplicationStackCollection', pipeline_response)
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
                raise ARMError(response=response)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    get_available_stacks_on_prem.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Web/availableStacks'}
