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

from ._configuration import ResourceMoverServiceAPIConfiguration
from .operations import MoveCollectionsOperations
from .operations import MoveResourcesOperations
from .operations import UnresolvedDependenciesOperations
from .operations import OperationsDiscoveryOperations
from . import models


class ResourceMoverServiceAPI(SDKClient):
    """A first party Azure service orchestrating the move of Azure resources from one Azure region to another or between zones within a region.

    :ivar config: Configuration for client.
    :vartype config: ResourceMoverServiceAPIConfiguration

    :ivar move_collections: MoveCollections operations
    :vartype move_collections: azure.mgmt.resourcemover.operations.MoveCollectionsOperations
    :ivar move_resources: MoveResources operations
    :vartype move_resources: azure.mgmt.resourcemover.operations.MoveResourcesOperations
    :ivar unresolved_dependencies: UnresolvedDependencies operations
    :vartype unresolved_dependencies: azure.mgmt.resourcemover.operations.UnresolvedDependenciesOperations
    :ivar operations_discovery: OperationsDiscovery operations
    :vartype operations_discovery: azure.mgmt.resourcemover.operations.OperationsDiscoveryOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The Subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ResourceMoverServiceAPIConfiguration(credentials, subscription_id, base_url)
        super(ResourceMoverServiceAPI, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-10-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.move_collections = MoveCollectionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.move_resources = MoveResourcesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.unresolved_dependencies = UnresolvedDependenciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations_discovery = OperationsDiscoveryOperations(
            self._client, self.config, self._serialize, self._deserialize)
