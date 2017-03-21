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
from .operations.autoscale_settings_operations import AutoscaleSettingsOperations
from .operations.service_diagnostic_settings_operations import ServiceDiagnosticSettingsOperations
from .operations.alert_rules_operations import AlertRulesOperations
from .operations.alert_rule_incidents_operations import AlertRuleIncidentsOperations
from .operations.log_profiles_operations import LogProfilesOperations
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
        if not isinstance(subscription_id, str):
            raise TypeError("Parameter 'subscription_id' must be str.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(MonitorManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('monitormanagementclient/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class MonitorManagementClient(object):
    """Composite Swagger for Monitor Management Client

    :ivar config: Configuration for client.
    :vartype config: MonitorManagementClientConfiguration

    :ivar autoscale_settings: AutoscaleSettings operations
    :vartype autoscale_settings: .operations.AutoscaleSettingsOperations
    :ivar service_diagnostic_settings: ServiceDiagnosticSettings operations
    :vartype service_diagnostic_settings: .operations.ServiceDiagnosticSettingsOperations
    :ivar alert_rules: AlertRules operations
    :vartype alert_rules: .operations.AlertRulesOperations
    :ivar alert_rule_incidents: AlertRuleIncidents operations
    :vartype alert_rule_incidents: .operations.AlertRuleIncidentsOperations
    :ivar log_profiles: LogProfiles operations
    :vartype log_profiles: .operations.LogProfilesOperations

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
        self.service_diagnostic_settings = ServiceDiagnosticSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.alert_rules = AlertRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.alert_rule_incidents = AlertRuleIncidentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.log_profiles = LogProfilesOperations(
            self._client, self.config, self._serialize, self._deserialize)
