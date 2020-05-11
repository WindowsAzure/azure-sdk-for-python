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

from ._configuration import EventHubManagementClientConfiguration
from .operations import NamespacesOperations
from .operations import DisasterRecoveryConfigsOperations
from .operations import EventHubsOperations
from .operations import ConsumerGroupsOperations
from .operations import Operations
from .operations import RegionsOperations
from . import models


class EventHubManagementClient(SDKClient):
    """Azure Event Hubs client

    :ivar config: Configuration for client.
    :vartype config: EventHubManagementClientConfiguration

    :ivar namespaces: Namespaces operations
    :vartype namespaces: azure.mgmt.eventhub.v2017_04_01.operations.NamespacesOperations
    :ivar disaster_recovery_configs: DisasterRecoveryConfigs operations
    :vartype disaster_recovery_configs: azure.mgmt.eventhub.v2017_04_01.operations.DisasterRecoveryConfigsOperations
    :ivar event_hubs: EventHubs operations
    :vartype event_hubs: azure.mgmt.eventhub.v2017_04_01.operations.EventHubsOperations
    :ivar consumer_groups: ConsumerGroups operations
    :vartype consumer_groups: azure.mgmt.eventhub.v2017_04_01.operations.ConsumerGroupsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.eventhub.v2017_04_01.operations.Operations
    :ivar regions: Regions operations
    :vartype regions: azure.mgmt.eventhub.v2017_04_01.operations.RegionsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials that uniquely identify a
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = EventHubManagementClientConfiguration(credentials, subscription_id, base_url)
        super(EventHubManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2017-04-01'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.namespaces = NamespacesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.disaster_recovery_configs = DisasterRecoveryConfigsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.event_hubs = EventHubsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.consumer_groups = ConsumerGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.regions = RegionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
