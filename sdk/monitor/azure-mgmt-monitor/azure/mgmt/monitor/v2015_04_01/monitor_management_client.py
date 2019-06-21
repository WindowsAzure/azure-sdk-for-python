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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.activity_logs_operations import ActivityLogsOperations
from .operations.autoscale_settings_operations import AutoscaleSettingsOperations
from .operations.event_categories_operations import EventCategoriesOperations
from .operations.operations import Operations
from .operations.tenant_activity_logs_operations import TenantActivityLogsOperations
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


class MonitorManagementClient(SDKClient):
    """Monitor Management Client

    :ivar config: Configuration for client.
    :vartype config: MonitorManagementClientConfiguration

    :ivar activity_logs: ActivityLogs operations
    :vartype activity_logs: azure.mgmt.monitor.v2015_04_01.operations.ActivityLogsOperations
    :ivar autoscale_settings: AutoscaleSettings operations
    :vartype autoscale_settings: azure.mgmt.monitor.v2015_04_01.operations.AutoscaleSettingsOperations
    :ivar event_categories: EventCategories operations
    :vartype event_categories: azure.mgmt.monitor.v2015_04_01.operations.EventCategoriesOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.monitor.v2015_04_01.operations.Operations
    :ivar tenant_activity_logs: TenantActivityLogs operations
    :vartype tenant_activity_logs: azure.mgmt.monitor.v2015_04_01.operations.TenantActivityLogsOperations

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
        super(MonitorManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2015-04-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.activity_logs = ActivityLogsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.autoscale_settings = AutoscaleSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.event_categories = EventCategoriesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tenant_activity_logs = TenantActivityLogsOperations(
            self._client, self.config, self._serialize, self._deserialize)
