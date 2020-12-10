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

class AlertsOperations:
    """AlertsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.alertsmanagement.models
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

    async def meta_data(
        self,
        identifier: Union[str, "_models.Identifier"],
        **kwargs
    ) -> "_models.AlertsMetaData":
        """List alerts meta data information based on value of identifier parameter.

        :param identifier: Identification of the information to be retrieved by API call.
        :type identifier: str or ~azure.mgmt.alertsmanagement.models.Identifier
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AlertsMetaData, or the result of cls(response)
        :rtype: ~azure.mgmt.alertsmanagement.models.AlertsMetaData
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.AlertsMetaData"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-05-05-preview"
        accept = "application/json"

        # Construct URL
        url = self.meta_data.metadata['url']  # type: ignore

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        query_parameters['identifier'] = self._serialize.query("identifier", identifier, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('AlertsMetaData', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    meta_data.metadata = {'url': '/providers/Microsoft.AlertsManagement/alertsMetaData'}  # type: ignore

    def get_all(
        self,
        target_resource: Optional[str] = None,
        target_resource_type: Optional[str] = None,
        target_resource_group: Optional[str] = None,
        monitor_service: Optional[Union[str, "_models.MonitorService"]] = None,
        monitor_condition: Optional[Union[str, "_models.MonitorCondition"]] = None,
        severity: Optional[Union[str, "_models.Severity"]] = None,
        alert_state: Optional[Union[str, "_models.AlertState"]] = None,
        alert_rule: Optional[str] = None,
        smart_group_id: Optional[str] = None,
        include_context: Optional[bool] = None,
        include_egress_config: Optional[bool] = None,
        page_count: Optional[int] = None,
        sort_by: Optional[Union[str, "_models.AlertsSortByFields"]] = None,
        sort_order: Optional[Union[str, "_models.Enum11"]] = None,
        select: Optional[str] = None,
        time_range: Optional[Union[str, "_models.TimeRange"]] = None,
        custom_time_range: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["_models.AlertsList"]:
        """List all existing alerts, where the results can be filtered on the basis of multiple parameters
        (e.g. time range). The results can then be sorted on the basis specific fields, with the
        default being lastModifiedDateTime.

        :param target_resource: Filter by target resource( which is full ARM ID) Default value is
         select all.
        :type target_resource: str
        :param target_resource_type: Filter by target resource type. Default value is select all.
        :type target_resource_type: str
        :param target_resource_group: Filter by target resource group name. Default value is select
         all.
        :type target_resource_group: str
        :param monitor_service: Filter by monitor service which generates the alert instance. Default
         value is select all.
        :type monitor_service: str or ~azure.mgmt.alertsmanagement.models.MonitorService
        :param monitor_condition: Filter by monitor condition which is either 'Fired' or 'Resolved'.
         Default value is to select all.
        :type monitor_condition: str or ~azure.mgmt.alertsmanagement.models.MonitorCondition
        :param severity: Filter by severity.  Default value is select all.
        :type severity: str or ~azure.mgmt.alertsmanagement.models.Severity
        :param alert_state: Filter by state of the alert instance. Default value is to select all.
        :type alert_state: str or ~azure.mgmt.alertsmanagement.models.AlertState
        :param alert_rule: Filter by specific alert rule.  Default value is to select all.
        :type alert_rule: str
        :param smart_group_id: Filter the alerts list by the Smart Group Id. Default value is none.
        :type smart_group_id: str
        :param include_context: Include context which has contextual data specific to the monitor
         service. Default value is false'.
        :type include_context: bool
        :param include_egress_config: Include egress config which would be used for displaying the
         content in portal.  Default value is 'false'.
        :type include_egress_config: bool
        :param page_count: Determines number of alerts returned per page in response. Permissible value
         is between 1 to 250. When the "includeContent"  filter is selected, maximum value allowed is
         25. Default value is 25.
        :type page_count: int
        :param sort_by: Sort the query results by input field,  Default value is
         'lastModifiedDateTime'.
        :type sort_by: str or ~azure.mgmt.alertsmanagement.models.AlertsSortByFields
        :param sort_order: Sort the query results order in either ascending or descending.  Default
         value is 'desc' for time fields and 'asc' for others.
        :type sort_order: str or ~azure.mgmt.alertsmanagement.models.Enum11
        :param select: This filter allows to selection of the fields(comma separated) which would  be
         part of the essential section. This would allow to project only the  required fields rather
         than getting entire content.  Default is to fetch all the fields in the essentials section.
        :type select: str
        :param time_range: Filter by time range by below listed values. Default value is 1 day.
        :type time_range: str or ~azure.mgmt.alertsmanagement.models.TimeRange
        :param custom_time_range: Filter by custom time range in the format :code:`<start-
         time>`/:code:`<end-time>`  where time is in (ISO-8601 format)'. Permissible values is within 30
         days from  query time. Either timeRange or customTimeRange could be used but not both. Default
         is none.
        :type custom_time_range: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either AlertsList or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.alertsmanagement.models.AlertsList]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.AlertsList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-05-05-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.get_all.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if target_resource is not None:
                    query_parameters['targetResource'] = self._serialize.query("target_resource", target_resource, 'str')
                if target_resource_type is not None:
                    query_parameters['targetResourceType'] = self._serialize.query("target_resource_type", target_resource_type, 'str')
                if target_resource_group is not None:
                    query_parameters['targetResourceGroup'] = self._serialize.query("target_resource_group", target_resource_group, 'str')
                if monitor_service is not None:
                    query_parameters['monitorService'] = self._serialize.query("monitor_service", monitor_service, 'str')
                if monitor_condition is not None:
                    query_parameters['monitorCondition'] = self._serialize.query("monitor_condition", monitor_condition, 'str')
                if severity is not None:
                    query_parameters['severity'] = self._serialize.query("severity", severity, 'str')
                if alert_state is not None:
                    query_parameters['alertState'] = self._serialize.query("alert_state", alert_state, 'str')
                if alert_rule is not None:
                    query_parameters['alertRule'] = self._serialize.query("alert_rule", alert_rule, 'str')
                if smart_group_id is not None:
                    query_parameters['smartGroupId'] = self._serialize.query("smart_group_id", smart_group_id, 'str')
                if include_context is not None:
                    query_parameters['includeContext'] = self._serialize.query("include_context", include_context, 'bool')
                if include_egress_config is not None:
                    query_parameters['includeEgressConfig'] = self._serialize.query("include_egress_config", include_egress_config, 'bool')
                if page_count is not None:
                    query_parameters['pageCount'] = self._serialize.query("page_count", page_count, 'int')
                if sort_by is not None:
                    query_parameters['sortBy'] = self._serialize.query("sort_by", sort_by, 'str')
                if sort_order is not None:
                    query_parameters['sortOrder'] = self._serialize.query("sort_order", sort_order, 'str')
                if select is not None:
                    query_parameters['select'] = self._serialize.query("select", select, 'str')
                if time_range is not None:
                    query_parameters['timeRange'] = self._serialize.query("time_range", time_range, 'str')
                if custom_time_range is not None:
                    query_parameters['customTimeRange'] = self._serialize.query("custom_time_range", custom_time_range, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('AlertsList', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(_models.ErrorResponseAutoGenerated, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    get_all.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.AlertsManagement/alerts'}  # type: ignore

    async def get_by_id(
        self,
        alert_id: str,
        **kwargs
    ) -> "_models.Alert":
        """Get a specific alert.

        Get information related to a specific alert.

        :param alert_id: Unique ID of an alert instance.
        :type alert_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Alert, or the result of cls(response)
        :rtype: ~azure.mgmt.alertsmanagement.models.Alert
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Alert"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-05-05-preview"
        accept = "application/json"

        # Construct URL
        url = self.get_by_id.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
            'alertId': self._serialize.url("alert_id", alert_id, 'str'),
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
            error = self._deserialize(_models.ErrorResponseAutoGenerated, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('Alert', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_by_id.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.AlertsManagement/alerts/{alertId}'}  # type: ignore

    async def change_state(
        self,
        alert_id: str,
        new_state: Union[str, "_models.AlertState"],
        **kwargs
    ) -> "_models.Alert":
        """Change the state of an alert.

        :param alert_id: Unique ID of an alert instance.
        :type alert_id: str
        :param new_state: New state of the alert.
        :type new_state: str or ~azure.mgmt.alertsmanagement.models.AlertState
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Alert, or the result of cls(response)
        :rtype: ~azure.mgmt.alertsmanagement.models.Alert
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Alert"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-05-05-preview"
        accept = "application/json"

        # Construct URL
        url = self.change_state.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
            'alertId': self._serialize.url("alert_id", alert_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        query_parameters['newState'] = self._serialize.query("new_state", new_state, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.ErrorResponseAutoGenerated, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('Alert', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    change_state.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.AlertsManagement/alerts/{alertId}/changestate'}  # type: ignore

    async def get_history(
        self,
        alert_id: str,
        **kwargs
    ) -> "_models.AlertModification":
        """Get the history of an alert, which captures any monitor condition changes (Fired/Resolved) and
        alert state changes (New/Acknowledged/Closed).

        :param alert_id: Unique ID of an alert instance.
        :type alert_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AlertModification, or the result of cls(response)
        :rtype: ~azure.mgmt.alertsmanagement.models.AlertModification
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.AlertModification"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-05-05-preview"
        accept = "application/json"

        # Construct URL
        url = self.get_history.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
            'alertId': self._serialize.url("alert_id", alert_id, 'str'),
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
            error = self._deserialize(_models.ErrorResponseAutoGenerated, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('AlertModification', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_history.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.AlertsManagement/alerts/{alertId}/history'}  # type: ignore

    async def get_summary(
        self,
        groupby: Union[str, "_models.AlertsSummaryGroupByFields"],
        include_smart_groups_count: Optional[bool] = None,
        target_resource: Optional[str] = None,
        target_resource_type: Optional[str] = None,
        target_resource_group: Optional[str] = None,
        monitor_service: Optional[Union[str, "_models.MonitorService"]] = None,
        monitor_condition: Optional[Union[str, "_models.MonitorCondition"]] = None,
        severity: Optional[Union[str, "_models.Severity"]] = None,
        alert_state: Optional[Union[str, "_models.AlertState"]] = None,
        alert_rule: Optional[str] = None,
        time_range: Optional[Union[str, "_models.TimeRange"]] = None,
        custom_time_range: Optional[str] = None,
        **kwargs
    ) -> "_models.AlertsSummary":
        """Get a summarized count of your alerts grouped by various parameters (e.g. grouping by
        'Severity' returns the count of alerts for each severity).

        :param groupby: This parameter allows the result set to be grouped by input fields (Maximum 2
         comma separated fields supported). For example, groupby=severity or
         groupby=severity,alertstate.
        :type groupby: str or ~azure.mgmt.alertsmanagement.models.AlertsSummaryGroupByFields
        :param include_smart_groups_count: Include count of the SmartGroups as part of the summary.
         Default value is 'false'.
        :type include_smart_groups_count: bool
        :param target_resource: Filter by target resource( which is full ARM ID) Default value is
         select all.
        :type target_resource: str
        :param target_resource_type: Filter by target resource type. Default value is select all.
        :type target_resource_type: str
        :param target_resource_group: Filter by target resource group name. Default value is select
         all.
        :type target_resource_group: str
        :param monitor_service: Filter by monitor service which generates the alert instance. Default
         value is select all.
        :type monitor_service: str or ~azure.mgmt.alertsmanagement.models.MonitorService
        :param monitor_condition: Filter by monitor condition which is either 'Fired' or 'Resolved'.
         Default value is to select all.
        :type monitor_condition: str or ~azure.mgmt.alertsmanagement.models.MonitorCondition
        :param severity: Filter by severity.  Default value is select all.
        :type severity: str or ~azure.mgmt.alertsmanagement.models.Severity
        :param alert_state: Filter by state of the alert instance. Default value is to select all.
        :type alert_state: str or ~azure.mgmt.alertsmanagement.models.AlertState
        :param alert_rule: Filter by specific alert rule.  Default value is to select all.
        :type alert_rule: str
        :param time_range: Filter by time range by below listed values. Default value is 1 day.
        :type time_range: str or ~azure.mgmt.alertsmanagement.models.TimeRange
        :param custom_time_range: Filter by custom time range in the format :code:`<start-
         time>`/:code:`<end-time>`  where time is in (ISO-8601 format)'. Permissible values is within 30
         days from  query time. Either timeRange or customTimeRange could be used but not both. Default
         is none.
        :type custom_time_range: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: AlertsSummary, or the result of cls(response)
        :rtype: ~azure.mgmt.alertsmanagement.models.AlertsSummary
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.AlertsSummary"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-05-05-preview"
        accept = "application/json"

        # Construct URL
        url = self.get_summary.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['groupby'] = self._serialize.query("groupby", groupby, 'str')
        if include_smart_groups_count is not None:
            query_parameters['includeSmartGroupsCount'] = self._serialize.query("include_smart_groups_count", include_smart_groups_count, 'bool')
        if target_resource is not None:
            query_parameters['targetResource'] = self._serialize.query("target_resource", target_resource, 'str')
        if target_resource_type is not None:
            query_parameters['targetResourceType'] = self._serialize.query("target_resource_type", target_resource_type, 'str')
        if target_resource_group is not None:
            query_parameters['targetResourceGroup'] = self._serialize.query("target_resource_group", target_resource_group, 'str')
        if monitor_service is not None:
            query_parameters['monitorService'] = self._serialize.query("monitor_service", monitor_service, 'str')
        if monitor_condition is not None:
            query_parameters['monitorCondition'] = self._serialize.query("monitor_condition", monitor_condition, 'str')
        if severity is not None:
            query_parameters['severity'] = self._serialize.query("severity", severity, 'str')
        if alert_state is not None:
            query_parameters['alertState'] = self._serialize.query("alert_state", alert_state, 'str')
        if alert_rule is not None:
            query_parameters['alertRule'] = self._serialize.query("alert_rule", alert_rule, 'str')
        if time_range is not None:
            query_parameters['timeRange'] = self._serialize.query("time_range", time_range, 'str')
        if custom_time_range is not None:
            query_parameters['customTimeRange'] = self._serialize.query("custom_time_range", custom_time_range, 'str')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(_models.ErrorResponseAutoGenerated, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('AlertsSummary', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_summary.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.AlertsManagement/alertsSummary'}  # type: ignore
