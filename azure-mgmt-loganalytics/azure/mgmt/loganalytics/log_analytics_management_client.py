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
from .operations.storage_insights_operations import StorageInsightsOperations
from .operations.workspaces_operations import WorkspacesOperations
from .operations.saved_searches_operations import SavedSearchesOperations
from .operations.operations import Operations
from . import models


class LogAnalyticsManagementClientConfiguration(AzureConfiguration):
    """Configuration for LogAnalyticsManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Gets subscription credentials which uniquely
     identify Microsoft Azure subscription. The subscription ID forms part of
     the URI for every service call.
    :type subscription_id: str
    :param purge_id: In a purge status request, this is the Id of the
     operation the status of which is returned.
    :type purge_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, purge_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if purge_id is None:
            raise ValueError("Parameter 'purge_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(LogAnalyticsManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-loganalytics/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id
        self.purge_id = purge_id


class LogAnalyticsManagementClient(SDKClient):
    """The Log Analytics Client.

    :ivar config: Configuration for client.
    :vartype config: LogAnalyticsManagementClientConfiguration

    :ivar storage_insights: StorageInsights operations
    :vartype storage_insights: azure.mgmt.loganalytics.operations.StorageInsightsOperations
    :ivar workspaces: Workspaces operations
    :vartype workspaces: azure.mgmt.loganalytics.operations.WorkspacesOperations
    :ivar saved_searches: SavedSearches operations
    :vartype saved_searches: azure.mgmt.loganalytics.operations.SavedSearchesOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.loganalytics.operations.Operations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Gets subscription credentials which uniquely
     identify Microsoft Azure subscription. The subscription ID forms part of
     the URI for every service call.
    :type subscription_id: str
    :param purge_id: In a purge status request, this is the Id of the
     operation the status of which is returned.
    :type purge_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, purge_id, base_url=None):

        self.config = LogAnalyticsManagementClientConfiguration(credentials, subscription_id, purge_id, base_url)
        super(LogAnalyticsManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2015-03-20'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.storage_insights = StorageInsightsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workspaces = WorkspacesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.saved_searches = SavedSearchesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
