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

from ._configuration import ServiceFabricClientAPIsConfiguration
from .operations import ServiceFabricClientAPIsOperationsMixin
from .operations import MeshSecretOperations
from .operations import MeshSecretValueOperations
from .operations import MeshVolumeOperations
from .operations import MeshNetworkOperations
from .operations import MeshApplicationOperations
from .operations import MeshServiceOperations
from .operations import MeshCodePackageOperations
from .operations import MeshServiceReplicaOperations
from .operations import MeshGatewayOperations
from . import models


class ServiceFabricClientAPIs(ServiceFabricClientAPIsOperationsMixin, SDKClient):
    """Service Fabric REST Client APIs allows management of Service Fabric clusters, applications and services.

    :ivar config: Configuration for client.
    :vartype config: ServiceFabricClientAPIsConfiguration

    :ivar mesh_secret: MeshSecret operations
    :vartype mesh_secret: azure.servicefabric.operations.MeshSecretOperations
    :ivar mesh_secret_value: MeshSecretValue operations
    :vartype mesh_secret_value: azure.servicefabric.operations.MeshSecretValueOperations
    :ivar mesh_volume: MeshVolume operations
    :vartype mesh_volume: azure.servicefabric.operations.MeshVolumeOperations
    :ivar mesh_network: MeshNetwork operations
    :vartype mesh_network: azure.servicefabric.operations.MeshNetworkOperations
    :ivar mesh_application: MeshApplication operations
    :vartype mesh_application: azure.servicefabric.operations.MeshApplicationOperations
    :ivar mesh_service: MeshService operations
    :vartype mesh_service: azure.servicefabric.operations.MeshServiceOperations
    :ivar mesh_code_package: MeshCodePackage operations
    :vartype mesh_code_package: azure.servicefabric.operations.MeshCodePackageOperations
    :ivar mesh_service_replica: MeshServiceReplica operations
    :vartype mesh_service_replica: azure.servicefabric.operations.MeshServiceReplicaOperations
    :ivar mesh_gateway: MeshGateway operations
    :vartype mesh_gateway: azure.servicefabric.operations.MeshGatewayOperations

    :param credentials: Subscription credentials which uniquely identify
     client subscription.
    :type credentials: None
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, base_url=None):

        self.config = ServiceFabricClientAPIsConfiguration(credentials, base_url)
        super(ServiceFabricClientAPIs, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '6.5.0.36'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.mesh_secret = MeshSecretOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mesh_secret_value = MeshSecretValueOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mesh_volume = MeshVolumeOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mesh_network = MeshNetworkOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mesh_application = MeshApplicationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mesh_service = MeshServiceOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mesh_code_package = MeshCodePackageOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mesh_service_replica = MeshServiceReplicaOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.mesh_gateway = MeshGatewayOperations(
            self._client, self.config, self._serialize, self._deserialize)
