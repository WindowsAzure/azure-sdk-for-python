# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.service_client import ServiceClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from msrest.pipeline import ClientRawResponse
from msrestazure.azure_exceptions import CloudError
import uuid
from .operations.autoscale_settings_operations import AutoscaleSettingsOperations
from .operations.operations import Operations
from .operations.alert_rule_incidents_operations import AlertRuleIncidentsOperations
from .operations.alert_rules_operations import AlertRulesOperations
from .operations.log_profiles_operations import LogProfilesOperations
from .operations.diagnostic_settings_operations import DiagnosticSettingsOperations
from .operations.diagnostic_settings_category_operations import DiagnosticSettingsCategoryOperations
from .operations.action_groups_operations import ActionGroupsOperations
from .operations.activity_log_alerts_operations import ActivityLogAlertsOperations
from .operations.activity_logs_operations import ActivityLogsOperations
from .operations.event_categories_operations import EventCategoriesOperations
from .operations.tenant_activity_logs_operations import TenantActivityLogsOperations
from .operations.metric_definitions_operations import MetricDefinitionsOperations
from .operations.metrics_operations import MetricsOperations
from .operations.metric_baseline_operations import MetricBaselineOperations
from .operations.metric_alerts_operations import MetricAlertsOperations
from .operations.metric_alerts_status_operations import MetricAlertsStatusOperations
from . import models


class MonitorManagementClientConfiguration(AzureConfiguration):
    """Configuration for MonitorManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The Azure subscription Id.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(MonitorManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-monitor/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class MonitorManagementClient(object):
    """Monitor Management Client

    :ivar config: Configuration for client.
    :vartype config: MonitorManagementClientConfiguration

    :ivar autoscale_settings: AutoscaleSettings operations
    :vartype autoscale_settings: azure.mgmt.monitor.operations.AutoscaleSettingsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.monitor.operations.Operations
    :ivar alert_rule_incidents: AlertRuleIncidents operations
    :vartype alert_rule_incidents: azure.mgmt.monitor.operations.AlertRuleIncidentsOperations
    :ivar alert_rules: AlertRules operations
    :vartype alert_rules: azure.mgmt.monitor.operations.AlertRulesOperations
    :ivar log_profiles: LogProfiles operations
    :vartype log_profiles: azure.mgmt.monitor.operations.LogProfilesOperations
    :ivar diagnostic_settings: DiagnosticSettings operations
    :vartype diagnostic_settings: azure.mgmt.monitor.operations.DiagnosticSettingsOperations
    :ivar diagnostic_settings_category: DiagnosticSettingsCategory operations
    :vartype diagnostic_settings_category: azure.mgmt.monitor.operations.DiagnosticSettingsCategoryOperations
    :ivar action_groups: ActionGroups operations
    :vartype action_groups: azure.mgmt.monitor.operations.ActionGroupsOperations
    :ivar activity_log_alerts: ActivityLogAlerts operations
    :vartype activity_log_alerts: azure.mgmt.monitor.operations.ActivityLogAlertsOperations
    :ivar activity_logs: ActivityLogs operations
    :vartype activity_logs: azure.mgmt.monitor.operations.ActivityLogsOperations
    :ivar event_categories: EventCategories operations
    :vartype event_categories: azure.mgmt.monitor.operations.EventCategoriesOperations
    :ivar tenant_activity_logs: TenantActivityLogs operations
    :vartype tenant_activity_logs: azure.mgmt.monitor.operations.TenantActivityLogsOperations
    :ivar metric_definitions: MetricDefinitions operations
    :vartype metric_definitions: azure.mgmt.monitor.operations.MetricDefinitionsOperations
    :ivar metrics: Metrics operations
    :vartype metrics: azure.mgmt.monitor.operations.MetricsOperations
    :ivar metric_baseline: MetricBaseline operations
    :vartype metric_baseline: azure.mgmt.monitor.operations.MetricBaselineOperations
    :ivar metric_alerts: MetricAlerts operations
    :vartype metric_alerts: azure.mgmt.monitor.operations.MetricAlertsOperations
    :ivar metric_alerts_status: MetricAlertsStatus operations
    :vartype metric_alerts_status: azure.mgmt.monitor.operations.MetricAlertsStatusOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The Azure subscription Id.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = MonitorManagementClientConfiguration(credentials, subscription_id, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.autoscale_settings = AutoscaleSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.alert_rule_incidents = AlertRuleIncidentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.alert_rules = AlertRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.log_profiles = LogProfilesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.diagnostic_settings = DiagnosticSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.diagnostic_settings_category = DiagnosticSettingsCategoryOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.action_groups = ActionGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.activity_log_alerts = ActivityLogAlertsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.activity_logs = ActivityLogsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.event_categories = EventCategoriesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tenant_activity_logs = TenantActivityLogsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.metric_definitions = MetricDefinitionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.metrics = MetricsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.metric_baseline = MetricBaselineOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.metric_alerts = MetricAlertsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.metric_alerts_status = MetricAlertsStatusOperations(
            self._client, self.config, self._serialize, self._deserialize)

    def create_or_update_scheduled_query_rules(
            self, resource_group_name, rule_name, parameters, custom_headers=None, raw=False, **operation_config):
        """Creates or updates an log search rule.
        Request method: PUT		Request URI:
        https://management.azure.com/subscriptions/{subscription-id}/resourceGroups/{resource-group-name}/providers/microsoft.insights/scheduledQueryRules/{logsearch-rule-name}?api-version={api-version}.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param rule_name: The name of the rule.
        :type rule_name: str
        :param parameters: The parameters of the rule to create or update.
        :type parameters: ~azure.mgmt.monitor.models.LogSearchRuleResource
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: LogSearchRuleResource or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.monitor.models.LogSearchRuleResource or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        api_version = "2018-04-16"

        # Construct URL
        url = self.create_or_update_scheduled_query_rules.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'ruleName': self._serialize.url("rule_name", rule_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(parameters, 'LogSearchRuleResource')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('LogSearchRuleResource', response)
        if response.status_code == 201:
            deserialized = self._deserialize('LogSearchRuleResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update_scheduled_query_rules.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/microsoft.insights/scheduledQueryRules/{ruleName}'}

    def get_scheduled_query_rule(
            self, resource_group_name, rule_name, custom_headers=None, raw=False, **operation_config):
        """Gets an Log Search rule.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param rule_name: The name of the rule.
        :type rule_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: LogSearchRuleResource or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.monitor.models.LogSearchRuleResource or
         ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        api_version = "2018-04-16"

        # Construct URL
        url = self.get_scheduled_query_rule.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'ruleName': self._serialize.url("rule_name", rule_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200, 404]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('LogSearchRuleResource', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_scheduled_query_rule.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/microsoft.insights/scheduledQueryRules/{ruleName}'}

    def delete_scheduled_query_rules(
            self, resource_group_name, rule_name, custom_headers=None, raw=False, **operation_config):
        """Deletes a Log Search rule.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param rule_name: The name of the rule.
        :type rule_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        api_version = "2018-04-16"

        # Construct URL
        url = self.delete_scheduled_query_rules.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'ruleName': self._serialize.url("rule_name", rule_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete_scheduled_query_rules.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/microsoft.insights/scheduledQueryRules/{ruleName}'}

    def get_list_scheduled_query_rules(
            self, resource_group_name, filter=None, custom_headers=None, raw=False, **operation_config):
        """List the Log Search rules within a resource group.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param filter: The filter to apply on the operation. For more
         information please see
         https://msdn.microsoft.com/en-us/library/azure/dn931934.aspx
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of LogSearchRuleResource
        :rtype:
         ~azure.mgmt.monitor.models.LogSearchRuleResourcePaged[~azure.mgmt.monitor.models.LogSearchRuleResource]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        api_version = "2018-04-16"

        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.get_list_scheduled_query_rules.metadata['url']
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Content-Type'] = 'application/json; charset=utf-8'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters)
            response = self._client.send(
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.LogSearchRuleResourcePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.LogSearchRuleResourcePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    get_list_scheduled_query_rules.metadata = {'url': '/subscriptions/{subscriptionId}/resourcegroups/{resourceGroupName}/providers/microsoft.insights/scheduledQueryRules'}
