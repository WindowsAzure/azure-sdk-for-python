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
from .operations.clusters_operations import ClustersOperations
from .operations.cluster_versions_operations import ClusterVersionsOperations
from .operations.operations import Operations
from .operations.application_type_operations import ApplicationTypeOperations
from .operations.version_operations import VersionOperations
from .operations.application_operations import ApplicationOperations
from .operations.service_operations import ServiceOperations
from . import models


class ServiceFabricManagementClientConfiguration(AzureConfiguration):
    """Configuration for ServiceFabricManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param application_name: The name of the application resource.
    :type application_name: str
    :param application_type_name: The name of the application type name
     resource
    :type application_type_name: str
    :param service_name: The name of the service resource in the format of
     {applicationName}~{serviceName}.
    :type service_name: str
    :param subscription_id: The customer subscription identifier
    :type subscription_id: str
    :param version: The application type version.
    :type version: str
    :param cluster: The cluster resource.
    :type cluster: :class:`Cluster <azure.mgmt.servicefabric.models.Cluster>`
    :param cluster_update_parameters: The parameters which contains the
     property value and property name which used to update the cluster
     configuration.
    :type cluster_update_parameters: :class:`ClusterUpdateParameters
     <azure.mgmt.servicefabric.models.ClusterUpdateParameters>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, application_name, application_type_name, service_name, subscription_id, version, cluster, cluster_update_parameters, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if application_name is None:
            raise ValueError("Parameter 'application_name' must not be None.")
        if not isinstance(application_name, str):
            raise TypeError("Parameter 'application_name' must be str.")
        if application_type_name is None:
            raise ValueError("Parameter 'application_type_name' must not be None.")
        if not isinstance(application_type_name, str):
            raise TypeError("Parameter 'application_type_name' must be str.")
        if service_name is None:
            raise ValueError("Parameter 'service_name' must not be None.")
        if not isinstance(service_name, str):
            raise TypeError("Parameter 'service_name' must be str.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not isinstance(subscription_id, str):
            raise TypeError("Parameter 'subscription_id' must be str.")
        if version is None:
            raise ValueError("Parameter 'version' must not be None.")
        if not isinstance(version, str):
            raise TypeError("Parameter 'version' must be str.")
        if cluster is None:
            raise ValueError("Parameter 'cluster' must not be None.")
        if cluster_update_parameters is None:
            raise ValueError("Parameter 'cluster_update_parameters' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(ServiceFabricManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('servicefabricmanagementclient/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.application_name = application_name
        self.application_type_name = application_type_name
        self.service_name = service_name
        self.subscription_id = subscription_id
        self.version = version
        self.cluster = cluster
        self.cluster_update_parameters = cluster_update_parameters


class ServiceFabricManagementClient(object):
    """Azure Service Fabric Resource Provider API Client

    :ivar config: Configuration for client.
    :vartype config: ServiceFabricManagementClientConfiguration

    :ivar clusters: Clusters operations
    :vartype clusters: azure.mgmt.servicefabric.operations.ClustersOperations
    :ivar cluster_versions: ClusterVersions operations
    :vartype cluster_versions: azure.mgmt.servicefabric.operations.ClusterVersionsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.servicefabric.operations.Operations
    :ivar application_type: ApplicationType operations
    :vartype application_type: azure.mgmt.servicefabric.operations.ApplicationTypeOperations
    :ivar version: Version operations
    :vartype version: azure.mgmt.servicefabric.operations.VersionOperations
    :ivar application: Application operations
    :vartype application: azure.mgmt.servicefabric.operations.ApplicationOperations
    :ivar service: Service operations
    :vartype service: azure.mgmt.servicefabric.operations.ServiceOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param application_name: The name of the application resource.
    :type application_name: str
    :param application_type_name: The name of the application type name
     resource
    :type application_type_name: str
    :param service_name: The name of the service resource in the format of
     {applicationName}~{serviceName}.
    :type service_name: str
    :param subscription_id: The customer subscription identifier
    :type subscription_id: str
    :param version: The application type version.
    :type version: str
    :param cluster: The cluster resource.
    :type cluster: :class:`Cluster <azure.mgmt.servicefabric.models.Cluster>`
    :param cluster_update_parameters: The parameters which contains the
     property value and property name which used to update the cluster
     configuration.
    :type cluster_update_parameters: :class:`ClusterUpdateParameters
     <azure.mgmt.servicefabric.models.ClusterUpdateParameters>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, application_name, application_type_name, service_name, subscription_id, version, cluster, cluster_update_parameters, base_url=None):

        self.config = ServiceFabricManagementClientConfiguration(credentials, application_name, application_type_name, service_name, subscription_id, version, cluster, cluster_update_parameters, base_url)
        self._client = ServiceClient(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2017-07-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.clusters = ClustersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.cluster_versions = ClusterVersionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.application_type = ApplicationTypeOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.version = VersionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.application = ApplicationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.service = ServiceOperations(
            self._client, self.config, self._serialize, self._deserialize)
