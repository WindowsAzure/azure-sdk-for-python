# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import Any, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class ReportsOperations:
    """ReportsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.frontdoor.models
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

    async def get_latency_scorecards(
        self,
        resource_group_name: str,
        profile_name: str,
        experiment_name: str,
        aggregation_interval: Union[str, "_models.LatencyScorecardAggregationInterval"],
        end_date_time_utc: Optional[str] = None,
        country: Optional[str] = None,
        **kwargs: Any
    ) -> "_models.LatencyScorecard":
        """Gets a Latency Scorecard for a given Experiment.

        Gets a Latency Scorecard for a given Experiment.

        :param resource_group_name: Name of the Resource group within the Azure subscription.
        :type resource_group_name: str
        :param profile_name: The Profile identifier associated with the Tenant and Partner.
        :type profile_name: str
        :param experiment_name: The Experiment identifier associated with the Experiment.
        :type experiment_name: str
        :param aggregation_interval: The aggregation interval of the Latency Scorecard.
        :type aggregation_interval: str or ~azure.mgmt.frontdoor.models.LatencyScorecardAggregationInterval
        :param end_date_time_utc: The end DateTime of the Latency Scorecard in UTC.
        :type end_date_time_utc: str
        :param country: The country associated with the Latency Scorecard. Values are country ISO codes
         as specified here- https://www.iso.org/iso-3166-country-codes.html.
        :type country: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: LatencyScorecard, or the result of cls(response)
        :rtype: ~azure.mgmt.frontdoor.models.LatencyScorecard
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.LatencyScorecard"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-11-01"
        accept = "application/json"

        # Construct URL
        url = self.get_latency_scorecards.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=80, min_length=1, pattern=r'^[a-zA-Z0-9_\-\(\)\.]*[^\.]$'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str', pattern=r'^[a-zA-Z0-9_\-\(\)\.]*[^\.]$'),
            'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', pattern=r'^[a-zA-Z0-9_\-\(\)\.]*[^\.]$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        if end_date_time_utc is not None:
            query_parameters['endDateTimeUTC'] = self._serialize.query("end_date_time_utc", end_date_time_utc, 'str')
        if country is not None:
            query_parameters['country'] = self._serialize.query("country", country, 'str')
        query_parameters['aggregationInterval'] = self._serialize.query("aggregation_interval", aggregation_interval, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('LatencyScorecard', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_latency_scorecards.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/NetworkExperimentProfiles/{profileName}/Experiments/{experimentName}/LatencyScorecard'}  # type: ignore

    async def get_timeseries(
        self,
        resource_group_name: str,
        profile_name: str,
        experiment_name: str,
        start_date_time_utc: datetime.datetime,
        end_date_time_utc: datetime.datetime,
        aggregation_interval: Union[str, "_models.TimeseriesAggregationInterval"],
        timeseries_type: Union[str, "_models.TimeseriesType"],
        endpoint: Optional[str] = None,
        country: Optional[str] = None,
        **kwargs: Any
    ) -> "_models.Timeseries":
        """Gets a Timeseries for a given Experiment.

        Gets a Timeseries for a given Experiment.

        :param resource_group_name: Name of the Resource group within the Azure subscription.
        :type resource_group_name: str
        :param profile_name: The Profile identifier associated with the Tenant and Partner.
        :type profile_name: str
        :param experiment_name: The Experiment identifier associated with the Experiment.
        :type experiment_name: str
        :param start_date_time_utc: The start DateTime of the Timeseries in UTC.
        :type start_date_time_utc: ~datetime.datetime
        :param end_date_time_utc: The end DateTime of the Timeseries in UTC.
        :type end_date_time_utc: ~datetime.datetime
        :param aggregation_interval: The aggregation interval of the Timeseries.
        :type aggregation_interval: str or ~azure.mgmt.frontdoor.models.TimeseriesAggregationInterval
        :param timeseries_type: The type of Timeseries.
        :type timeseries_type: str or ~azure.mgmt.frontdoor.models.TimeseriesType
        :param endpoint: The specific endpoint.
        :type endpoint: str
        :param country: The country associated with the Timeseries. Values are country ISO codes as
         specified here- https://www.iso.org/iso-3166-country-codes.html.
        :type country: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Timeseries, or the result of cls(response)
        :rtype: ~azure.mgmt.frontdoor.models.Timeseries
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Timeseries"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-11-01"
        accept = "application/json"

        # Construct URL
        url = self.get_timeseries.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=80, min_length=1, pattern=r'^[a-zA-Z0-9_\-\(\)\.]*[^\.]$'),
            'profileName': self._serialize.url("profile_name", profile_name, 'str', pattern=r'^[a-zA-Z0-9_\-\(\)\.]*[^\.]$'),
            'experimentName': self._serialize.url("experiment_name", experiment_name, 'str', pattern=r'^[a-zA-Z0-9_\-\(\)\.]*[^\.]$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        query_parameters['startDateTimeUTC'] = self._serialize.query("start_date_time_utc", start_date_time_utc, 'iso-8601')
        query_parameters['endDateTimeUTC'] = self._serialize.query("end_date_time_utc", end_date_time_utc, 'iso-8601')
        query_parameters['aggregationInterval'] = self._serialize.query("aggregation_interval", aggregation_interval, 'str')
        query_parameters['timeseriesType'] = self._serialize.query("timeseries_type", timeseries_type, 'str')
        if endpoint is not None:
            query_parameters['endpoint'] = self._serialize.query("endpoint", endpoint, 'str')
        if country is not None:
            query_parameters['country'] = self._serialize.query("country", country, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('Timeseries', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_timeseries.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/NetworkExperimentProfiles/{profileName}/Experiments/{experimentName}/Timeseries'}  # type: ignore
