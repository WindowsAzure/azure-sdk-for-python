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

from ._configuration import TimeSeriesInsightsClientConfiguration
from .operations import Operations
from .operations import EnvironmentsOperations
from .operations import EventSourcesOperations
from .operations import ReferenceDataSetsOperations
from .operations import AccessPoliciesOperations
from . import models


class TimeSeriesInsightsClient(SDKClient):
    """Time Series Insights client

    :ivar config: Configuration for client.
    :vartype config: TimeSeriesInsightsClientConfiguration

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.timeseriesinsights.operations.Operations
    :ivar environments: Environments operations
    :vartype environments: azure.mgmt.timeseriesinsights.operations.EnvironmentsOperations
    :ivar event_sources: EventSources operations
    :vartype event_sources: azure.mgmt.timeseriesinsights.operations.EventSourcesOperations
    :ivar reference_data_sets: ReferenceDataSets operations
    :vartype reference_data_sets: azure.mgmt.timeseriesinsights.operations.ReferenceDataSetsOperations
    :ivar access_policies: AccessPolicies operations
    :vartype access_policies: azure.mgmt.timeseriesinsights.operations.AccessPoliciesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure Subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = TimeSeriesInsightsClientConfiguration(credentials, subscription_id, base_url)
        super(TimeSeriesInsightsClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2020-05-15'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.environments = EnvironmentsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.event_sources = EventSourcesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.reference_data_sets = ReferenceDataSetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.access_policies = AccessPoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
