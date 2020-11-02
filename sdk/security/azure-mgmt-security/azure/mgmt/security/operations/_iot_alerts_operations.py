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
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

from .. import models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class IotAlertsOperations(object):
    """IotAlertsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.security.models
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
        resource_group_name,  # type: str
        solution_name,  # type: str
        min_start_time_utc=None,  # type: Optional[str]
        max_start_time_utc=None,  # type: Optional[str]
        alert_type=None,  # type: Optional[str]
        compromised_entity=None,  # type: Optional[str]
        limit=None,  # type: Optional[int]
        skip_token=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.IotAlertList"]
        """List IoT alerts.

        :param resource_group_name: The name of the resource group within the user's subscription. The
         name is case insensitive.
        :type resource_group_name: str
        :param solution_name: The name of the IoT Security solution.
        :type solution_name: str
        :param min_start_time_utc: Filter by minimum startTimeUtc (ISO 8601 format).
        :type min_start_time_utc: str
        :param max_start_time_utc: Filter by maximum startTimeUtc (ISO 8601 format).
        :type max_start_time_utc: str
        :param alert_type: Filter by alert type.
        :type alert_type: str
        :param compromised_entity: Filter by compromised device.
        :type compromised_entity: str
        :param limit: Limit the number of items returned in a single page.
        :type limit: int
        :param skip_token: Skip token used for pagination.
        :type skip_token: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either IotAlertList or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.security.models.IotAlertList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.IotAlertList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-08-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', pattern=r'^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
                    'solutionName': self._serialize.url("solution_name", solution_name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if min_start_time_utc is not None:
                    query_parameters['startTimeUtc>'] = self._serialize.query("min_start_time_utc", min_start_time_utc, 'str')
                if max_start_time_utc is not None:
                    query_parameters['startTimeUtc<'] = self._serialize.query("max_start_time_utc", max_start_time_utc, 'str')
                if alert_type is not None:
                    query_parameters['alertType'] = self._serialize.query("alert_type", alert_type, 'str')
                if compromised_entity is not None:
                    query_parameters['compromisedEntity'] = self._serialize.query("compromised_entity", compromised_entity, 'str')
                if limit is not None:
                    query_parameters['$limit'] = self._serialize.query("limit", limit, 'int')
                if skip_token is not None:
                    query_parameters['$skipToken'] = self._serialize.query("skip_token", skip_token, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('IotAlertList', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Security/iotSecuritySolutions/{solutionName}/iotAlerts'}  # type: ignore

    def get(
        self,
        resource_group_name,  # type: str
        solution_name,  # type: str
        iot_alert_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.IotAlert"
        """Get IoT alert.

        :param resource_group_name: The name of the resource group within the user's subscription. The
         name is case insensitive.
        :type resource_group_name: str
        :param solution_name: The name of the IoT Security solution.
        :type solution_name: str
        :param iot_alert_id: Id of the alert.
        :type iot_alert_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: IotAlert, or the result of cls(response)
        :rtype: ~azure.mgmt.security.models.IotAlert
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.IotAlert"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-08-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', pattern=r'^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1, pattern=r'^[-\w\._\(\)]+$'),
            'solutionName': self._serialize.url("solution_name", solution_name, 'str'),
            'iotAlertId': self._serialize.url("iot_alert_id", iot_alert_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('IotAlert', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Security/iotSecuritySolutions/{solutionName}/iotAlerts/{iotAlertId}'}  # type: ignore
