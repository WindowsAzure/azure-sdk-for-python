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

from ._configuration import PeeringManagementClientConfiguration
from .operations import PeeringManagementClientOperationsMixin
from .operations import LegacyPeeringsOperations
from .operations import Operations
from .operations import PeerAsnsOperations
from .operations import PeeringLocationsOperations
from .operations import PeeringsOperations
from .operations import PeeringServiceLocationsOperations
from .operations import PrefixesOperations
from .operations import PeeringServiceProvidersOperations
from .operations import PeeringServicesOperations
from . import models


class PeeringManagementClient(PeeringManagementClientOperationsMixin, SDKClient):
    """Peering Client

    :ivar config: Configuration for client.
    :vartype config: PeeringManagementClientConfiguration

    :ivar legacy_peerings: LegacyPeerings operations
    :vartype legacy_peerings: azure.mgmt.peering.operations.LegacyPeeringsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.peering.operations.Operations
    :ivar peer_asns: PeerAsns operations
    :vartype peer_asns: azure.mgmt.peering.operations.PeerAsnsOperations
    :ivar peering_locations: PeeringLocations operations
    :vartype peering_locations: azure.mgmt.peering.operations.PeeringLocationsOperations
    :ivar peerings: Peerings operations
    :vartype peerings: azure.mgmt.peering.operations.PeeringsOperations
    :ivar peering_service_locations: PeeringServiceLocations operations
    :vartype peering_service_locations: azure.mgmt.peering.operations.PeeringServiceLocationsOperations
    :ivar prefixes: Prefixes operations
    :vartype prefixes: azure.mgmt.peering.operations.PrefixesOperations
    :ivar peering_service_providers: PeeringServiceProviders operations
    :vartype peering_service_providers: azure.mgmt.peering.operations.PeeringServiceProvidersOperations
    :ivar peering_services: PeeringServices operations
    :vartype peering_services: azure.mgmt.peering.operations.PeeringServicesOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The Azure subscription ID.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = PeeringManagementClientConfiguration(credentials, subscription_id, base_url)
        super(PeeringManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2019-09-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.legacy_peerings = LegacyPeeringsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peer_asns = PeerAsnsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_locations = PeeringLocationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peerings = PeeringsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_service_locations = PeeringServiceLocationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.prefixes = PrefixesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_service_providers = PeeringServiceProvidersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.peering_services = PeeringServicesOperations(
            self._client, self.config, self._serialize, self._deserialize)
