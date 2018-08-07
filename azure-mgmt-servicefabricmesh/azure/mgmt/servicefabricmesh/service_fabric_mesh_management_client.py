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
from .operations.application_operations import ApplicationOperations
from .operations.service_operations import ServiceOperations
from .operations.replica_operations import ReplicaOperations
from .operations.code_package_operations import CodePackageOperations
from .operations.operations import Operations
from .operations.network_operations import NetworkOperations
from .operations.volume_operations import VolumeOperations
from . import models


class ServiceFabricMeshManagementClientConfiguration(AzureConfiguration):
    """Configuration for ServiceFabricMeshManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The customer subscription identifier
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

        super(ServiceFabricMeshManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-servicefabricmesh/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class ServiceFabricMeshManagementClient(SDKClient):
    """Service Fabric Mesh Management Client

    :ivar config: Configuration for client.
    :vartype config: ServiceFabricMeshManagementClientConfiguration

    :ivar application: Application operations
    :vartype application: azure.mgmt.servicefabricmesh.operations.ApplicationOperations
    :ivar service: Service operations
    :vartype service: azure.mgmt.servicefabricmesh.operations.ServiceOperations
    :ivar replica: Replica operations
    :vartype replica: azure.mgmt.servicefabricmesh.operations.ReplicaOperations
    :ivar code_package: CodePackage operations
    :vartype code_package: azure.mgmt.servicefabricmesh.operations.CodePackageOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.servicefabricmesh.operations.Operations
    :ivar network: Network operations
    :vartype network: azure.mgmt.servicefabricmesh.operations.NetworkOperations
    :ivar volume: Volume operations
    :vartype volume: azure.mgmt.servicefabricmesh.operations.VolumeOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The customer subscription identifier
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ServiceFabricMeshManagementClientConfiguration(credentials, subscription_id, base_url)
        super(ServiceFabricMeshManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-07-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.application = ApplicationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.service = ServiceOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.replica = ReplicaOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.code_package = CodePackageOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network = NetworkOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.volume = VolumeOperations(
            self._client, self.config, self._serialize, self._deserialize)
