# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.mgmt.core.exceptions import ARMErrorFormat

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class HealthMonitorsOperations(object):
    """HealthMonitorsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~workload_monitor_api.models
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

    def list(
        self,
        subscription_id,  # type: str
        resource_group_name,  # type: str
        provider_name,  # type: str
        resource_collection_name,  # type: str
        resource_name,  # type: str
        filter=None,  # type: Optional[str]
        expand=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["_models.HealthMonitorList"]
        """Get the current health status of all monitors of a virtual machine. Optional parameters: $expand (retrieve the monitor's evidence and configuration) and $filter (filter by monitor name).

        Get the current health status of all monitors of a virtual machine. Optional parameters:
        $expand (retrieve the monitor's evidence and configuration) and $filter (filter by monitor
        name).

        :param subscription_id: The subscription Id of the virtual machine.
        :type subscription_id: str
        :param resource_group_name: The resource group of the virtual machine.
        :type resource_group_name: str
        :param provider_name: The provider name (ex: Microsoft.Compute for virtual machines).
        :type provider_name: str
        :param resource_collection_name: The resource collection name (ex: virtualMachines for virtual
         machines).
        :type resource_collection_name: str
        :param resource_name: The name of the virtual machine.
        :type resource_name: str
        :param filter: Optionally filter by monitor name. Example: $filter=monitorName eq
         'logical-disks|C:|disk-free-space-mb.'.
        :type filter: str
        :param expand: Optionally expand the monitor’s evidence and/or configuration. Example:
         $expand=evidence,configuration.
        :type expand: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either HealthMonitorList or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~workload_monitor_api.models.HealthMonitorList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.HealthMonitorList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-01-13-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'providerName': self._serialize.url("provider_name", provider_name, 'str'),
                    'resourceCollectionName': self._serialize.url("resource_collection_name", resource_collection_name, 'str'),
                    'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if expand is not None:
                    query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('HealthMonitorList', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{providerName}/{resourceCollectionName}/{resourceName}/providers/Microsoft.WorkloadMonitor/monitors'}  # type: ignore

    def get(
        self,
        subscription_id,  # type: str
        resource_group_name,  # type: str
        provider_name,  # type: str
        resource_collection_name,  # type: str
        resource_name,  # type: str
        monitor_id,  # type: str
        expand=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.HealthMonitor"
        """Get the current health status of a monitor of a virtual machine. Optional parameter: $expand (retrieve the monitor's evidence and configuration).

        Get the current health status of a monitor of a virtual machine. Optional parameter: $expand
        (retrieve the monitor's evidence and configuration).

        :param subscription_id: The subscription Id of the virtual machine.
        :type subscription_id: str
        :param resource_group_name: The resource group of the virtual machine.
        :type resource_group_name: str
        :param provider_name: The provider name (ex: Microsoft.Compute for virtual machines).
        :type provider_name: str
        :param resource_collection_name: The resource collection name (ex: virtualMachines for virtual
         machines).
        :type resource_collection_name: str
        :param resource_name: The name of the virtual machine.
        :type resource_name: str
        :param monitor_id: The monitor Id of the virtual machine.
        :type monitor_id: str
        :param expand: Optionally expand the monitor’s evidence and/or configuration. Example:
         $expand=evidence,configuration.
        :type expand: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: HealthMonitor, or the result of cls(response)
        :rtype: ~workload_monitor_api.models.HealthMonitor
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.HealthMonitor"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-01-13-preview"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'providerName': self._serialize.url("provider_name", provider_name, 'str'),
            'resourceCollectionName': self._serialize.url("resource_collection_name", resource_collection_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'monitorId': self._serialize.url("monitor_id", monitor_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        if expand is not None:
            query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('HealthMonitor', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{providerName}/{resourceCollectionName}/{resourceName}/providers/Microsoft.WorkloadMonitor/monitors/{monitorId}'}  # type: ignore

    def list_state_changes(
        self,
        subscription_id,  # type: str
        resource_group_name,  # type: str
        provider_name,  # type: str
        resource_collection_name,  # type: str
        resource_name,  # type: str
        monitor_id,  # type: str
        filter=None,  # type: Optional[str]
        expand=None,  # type: Optional[str]
        start_timestamp_utc=None,  # type: Optional[datetime.datetime]
        end_timestamp_utc=None,  # type: Optional[datetime.datetime]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["_models.HealthMonitorStateChangeList"]
        """Get the health state changes of a monitor of a virtual machine within the provided time window (default is the last 24 hours). Optional parameters: $expand (retrieve the monitor's evidence and configuration) and $filter (filter by heartbeat condition).

        Get the health state changes of a monitor of a virtual machine within the provided time window
        (default is the last 24 hours). Optional parameters: $expand (retrieve the monitor's evidence
        and configuration) and $filter (filter by heartbeat condition).

        :param subscription_id: The subscription Id of the virtual machine.
        :type subscription_id: str
        :param resource_group_name: The resource group of the virtual machine.
        :type resource_group_name: str
        :param provider_name: The provider name (ex: Microsoft.Compute for virtual machines).
        :type provider_name: str
        :param resource_collection_name: The resource collection name (ex: virtualMachines for virtual
         machines).
        :type resource_collection_name: str
        :param resource_name: The name of the virtual machine.
        :type resource_name: str
        :param monitor_id: The monitor Id of the virtual machine.
        :type monitor_id: str
        :param filter: Optionally filter by heartbeat condition. Example: $filter=isHeartbeat eq false.
        :type filter: str
        :param expand: Optionally expand the monitor’s evidence and/or configuration. Example:
         $expand=evidence,configuration.
        :type expand: str
        :param start_timestamp_utc: The start of the time window.
        :type start_timestamp_utc: ~datetime.datetime
        :param end_timestamp_utc: The end of the time window.
        :type end_timestamp_utc: ~datetime.datetime
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either HealthMonitorStateChangeList or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~workload_monitor_api.models.HealthMonitorStateChangeList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.HealthMonitorStateChangeList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-01-13-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_state_changes.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'providerName': self._serialize.url("provider_name", provider_name, 'str'),
                    'resourceCollectionName': self._serialize.url("resource_collection_name", resource_collection_name, 'str'),
                    'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
                    'monitorId': self._serialize.url("monitor_id", monitor_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if expand is not None:
                    query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
                if start_timestamp_utc is not None:
                    query_parameters['startTimestampUtc'] = self._serialize.query("start_timestamp_utc", start_timestamp_utc, 'iso-8601')
                if end_timestamp_utc is not None:
                    query_parameters['endTimestampUtc'] = self._serialize.query("end_timestamp_utc", end_timestamp_utc, 'iso-8601')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('HealthMonitorStateChangeList', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_state_changes.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{providerName}/{resourceCollectionName}/{resourceName}/providers/Microsoft.WorkloadMonitor/monitors/{monitorId}/history'}  # type: ignore

    def get_state_change(
        self,
        subscription_id,  # type: str
        resource_group_name,  # type: str
        provider_name,  # type: str
        resource_collection_name,  # type: str
        resource_name,  # type: str
        monitor_id,  # type: str
        timestamp_unix,  # type: str
        expand=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.HealthMonitorStateChange"
        """Get the health state change of a monitor of a virtual machine at the provided timestamp. Optional parameter: $expand (retrieve the monitor's evidence and configuration).

        Get the health state change of a monitor of a virtual machine at the provided timestamp.
        Optional parameter: $expand (retrieve the monitor's evidence and configuration).

        :param subscription_id: The subscription Id of the virtual machine.
        :type subscription_id: str
        :param resource_group_name: The resource group of the virtual machine.
        :type resource_group_name: str
        :param provider_name: The provider name (ex: Microsoft.Compute for virtual machines).
        :type provider_name: str
        :param resource_collection_name: The resource collection name (ex: virtualMachines for virtual
         machines).
        :type resource_collection_name: str
        :param resource_name: The name of the virtual machine.
        :type resource_name: str
        :param monitor_id: The monitor Id of the virtual machine.
        :type monitor_id: str
        :param timestamp_unix: The timestamp of the state change (unix format).
        :type timestamp_unix: str
        :param expand: Optionally expand the monitor’s evidence and/or configuration. Example:
         $expand=evidence,configuration.
        :type expand: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: HealthMonitorStateChange, or the result of cls(response)
        :rtype: ~workload_monitor_api.models.HealthMonitorStateChange
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.HealthMonitorStateChange"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-01-13-preview"
        accept = "application/json"

        # Construct URL
        url = self.get_state_change.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("subscription_id", subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'providerName': self._serialize.url("provider_name", provider_name, 'str'),
            'resourceCollectionName': self._serialize.url("resource_collection_name", resource_collection_name, 'str'),
            'resourceName': self._serialize.url("resource_name", resource_name, 'str'),
            'monitorId': self._serialize.url("monitor_id", monitor_id, 'str'),
            'timestampUnix': self._serialize.url("timestamp_unix", timestamp_unix, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        if expand is not None:
            query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('HealthMonitorStateChange', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_state_change.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{providerName}/{resourceCollectionName}/{resourceName}/providers/Microsoft.WorkloadMonitor/monitors/{monitorId}/history/{timestampUnix}'}  # type: ignore
