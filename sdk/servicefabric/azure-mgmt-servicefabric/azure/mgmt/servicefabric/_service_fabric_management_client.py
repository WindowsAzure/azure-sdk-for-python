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

from ._configuration import ServiceFabricManagementClientConfiguration
from .operations import ClustersOperations
from .operations import ClusterVersionsOperations
from .operations import Operations
from .operations import ApplicationTypesOperations
from .operations import ApplicationTypeVersionsOperations
from .operations import ApplicationsOperations
from .operations import ServicesOperations
from . import models


class ServiceFabricManagementClient(SDKClient):
    """Service Fabric Management Client

    :ivar config: Configuration for client.
    :vartype config: ServiceFabricManagementClientConfiguration

    :ivar clusters: Clusters operations
    :vartype clusters: azure.mgmt.servicefabric.operations.ClustersOperations
    :ivar cluster_versions: ClusterVersions operations
    :vartype cluster_versions: azure.mgmt.servicefabric.operations.ClusterVersionsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.servicefabric.operations.Operations
    :ivar application_types: ApplicationTypes operations
    :vartype application_types: azure.mgmt.servicefabric.operations.ApplicationTypesOperations
    :ivar application_type_versions: ApplicationTypeVersions operations
    :vartype application_type_versions: azure.mgmt.servicefabric.operations.ApplicationTypeVersionsOperations
    :ivar applications: Applications operations
    :vartype applications: azure.mgmt.servicefabric.operations.ApplicationsOperations
    :ivar services: Services operations
    :vartype services: azure.mgmt.servicefabric.operations.ServicesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The customer subscription identifier.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ServiceFabricManagementClientConfiguration(credentials, subscription_id, base_url)
        super(ServiceFabricManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-06-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.clusters = ClustersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.cluster_versions = ClusterVersionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.application_types = ApplicationTypesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.application_type_versions = ApplicationTypeVersionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.applications = ApplicationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.services = ServicesOperations(
            self._client, self.config, self._serialize, self._deserialize)
