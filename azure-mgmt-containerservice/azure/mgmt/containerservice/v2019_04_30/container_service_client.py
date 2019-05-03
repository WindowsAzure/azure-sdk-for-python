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
from .operations.open_shift_managed_clusters_operations import OpenShiftManagedClustersOperations
from .operations.operations import Operations
from .operations.managed_clusters_operations import ManagedClustersOperations
from .operations.agent_pools_operations import AgentPoolsOperations
from .operations.container_services_operations import ContainerServicesOperations
from . import models


class ContainerServiceClientConfiguration(AzureConfiguration):
    """Configuration for ContainerServiceClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
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

        super(ContainerServiceClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-containerservice/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class ContainerServiceClient(SDKClient):
    """The Container Service Client.

    :ivar config: Configuration for client.
    :vartype config: ContainerServiceClientConfiguration

    :ivar open_shift_managed_clusters: OpenShiftManagedClusters operations
    :vartype open_shift_managed_clusters: azure.mgmt.containerservice.v2019_04_30.operations.OpenShiftManagedClustersOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.containerservice.v2019_04_30.operations.Operations
    :ivar managed_clusters: ManagedClusters operations
    :vartype managed_clusters: azure.mgmt.containerservice.v2019_04_30.operations.ManagedClustersOperations
    :ivar agent_pools: AgentPools operations
    :vartype agent_pools: azure.mgmt.containerservice.v2019_04_30.operations.AgentPoolsOperations
    :ivar container_services: ContainerServices operations
    :vartype container_services: azure.mgmt.containerservice.v2019_04_30.operations.ContainerServicesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ContainerServiceClientConfiguration(credentials, subscription_id, base_url)
        super(ContainerServiceClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.open_shift_managed_clusters = OpenShiftManagedClustersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_clusters = ManagedClustersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.agent_pools = AgentPoolsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.container_services = ContainerServicesOperations(
            self._client, self.config, self._serialize, self._deserialize)
