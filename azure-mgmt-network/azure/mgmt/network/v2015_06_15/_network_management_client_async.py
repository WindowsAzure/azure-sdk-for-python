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

from msrest.async_client import SDKClientAsync
from msrest import Serializer, Deserializer

from ._configuration import NetworkManagementClientConfiguration
from .operations_async import NetworkManagementClientOperationsMixin
from .operations_async import ApplicationGatewaysOperations
from .operations_async import ExpressRouteCircuitAuthorizationsOperations
from .operations_async import ExpressRouteCircuitPeeringsOperations
from .operations_async import ExpressRouteCircuitsOperations
from .operations_async import ExpressRouteServiceProvidersOperations
from .operations_async import LoadBalancersOperations
from .operations_async import NetworkInterfacesOperations
from .operations_async import NetworkSecurityGroupsOperations
from .operations_async import SecurityRulesOperations
from .operations_async import PublicIPAddressesOperations
from .operations_async import RouteTablesOperations
from .operations_async import RoutesOperations
from .operations_async import UsagesOperations
from .operations_async import VirtualNetworksOperations
from .operations_async import SubnetsOperations
from .operations_async import VirtualNetworkGatewaysOperations
from .operations_async import VirtualNetworkGatewayConnectionsOperations
from .operations_async import LocalNetworkGatewaysOperations
from . import models


class NetworkManagementClientAsync(NetworkManagementClientOperationsMixin, SDKClientAsync):
    """Network Client

    :ivar config: Configuration for client.
    :vartype config: NetworkManagementClientConfiguration

    :ivar application_gateways: ApplicationGateways operations
    :vartype application_gateways: azure.mgmt.network.v2015_06_15.operations.ApplicationGatewaysOperations
    :ivar express_route_circuit_authorizations: ExpressRouteCircuitAuthorizations operations
    :vartype express_route_circuit_authorizations: azure.mgmt.network.v2015_06_15.operations.ExpressRouteCircuitAuthorizationsOperations
    :ivar express_route_circuit_peerings: ExpressRouteCircuitPeerings operations
    :vartype express_route_circuit_peerings: azure.mgmt.network.v2015_06_15.operations.ExpressRouteCircuitPeeringsOperations
    :ivar express_route_circuits: ExpressRouteCircuits operations
    :vartype express_route_circuits: azure.mgmt.network.v2015_06_15.operations.ExpressRouteCircuitsOperations
    :ivar express_route_service_providers: ExpressRouteServiceProviders operations
    :vartype express_route_service_providers: azure.mgmt.network.v2015_06_15.operations.ExpressRouteServiceProvidersOperations
    :ivar load_balancers: LoadBalancers operations
    :vartype load_balancers: azure.mgmt.network.v2015_06_15.operations.LoadBalancersOperations
    :ivar network_interfaces: NetworkInterfaces operations
    :vartype network_interfaces: azure.mgmt.network.v2015_06_15.operations.NetworkInterfacesOperations
    :ivar network_security_groups: NetworkSecurityGroups operations
    :vartype network_security_groups: azure.mgmt.network.v2015_06_15.operations.NetworkSecurityGroupsOperations
    :ivar security_rules: SecurityRules operations
    :vartype security_rules: azure.mgmt.network.v2015_06_15.operations.SecurityRulesOperations
    :ivar public_ip_addresses: PublicIPAddresses operations
    :vartype public_ip_addresses: azure.mgmt.network.v2015_06_15.operations.PublicIPAddressesOperations
    :ivar route_tables: RouteTables operations
    :vartype route_tables: azure.mgmt.network.v2015_06_15.operations.RouteTablesOperations
    :ivar routes: Routes operations
    :vartype routes: azure.mgmt.network.v2015_06_15.operations.RoutesOperations
    :ivar usages: Usages operations
    :vartype usages: azure.mgmt.network.v2015_06_15.operations.UsagesOperations
    :ivar virtual_networks: VirtualNetworks operations
    :vartype virtual_networks: azure.mgmt.network.v2015_06_15.operations.VirtualNetworksOperations
    :ivar subnets: Subnets operations
    :vartype subnets: azure.mgmt.network.v2015_06_15.operations.SubnetsOperations
    :ivar virtual_network_gateways: VirtualNetworkGateways operations
    :vartype virtual_network_gateways: azure.mgmt.network.v2015_06_15.operations.VirtualNetworkGatewaysOperations
    :ivar virtual_network_gateway_connections: VirtualNetworkGatewayConnections operations
    :vartype virtual_network_gateway_connections: azure.mgmt.network.v2015_06_15.operations.VirtualNetworkGatewayConnectionsOperations
    :ivar local_network_gateways: LocalNetworkGateways operations
    :vartype local_network_gateways: azure.mgmt.network.v2015_06_15.operations.LocalNetworkGatewaysOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The subscription credentials which uniquely
     identify the Microsoft Azure subscription. The subscription ID forms part
     of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = NetworkManagementClientConfiguration(credentials, subscription_id, base_url)
        super(NetworkManagementClientAsync, self).__init__(self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2015-06-15'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.application_gateways = ApplicationGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.express_route_circuit_authorizations = ExpressRouteCircuitAuthorizationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.express_route_circuit_peerings = ExpressRouteCircuitPeeringsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.express_route_circuits = ExpressRouteCircuitsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.express_route_service_providers = ExpressRouteServiceProvidersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.load_balancers = LoadBalancersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_interfaces = NetworkInterfacesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_security_groups = NetworkSecurityGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.security_rules = SecurityRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.public_ip_addresses = PublicIPAddressesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.route_tables = RouteTablesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.routes = RoutesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.usages = UsagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_networks = VirtualNetworksOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subnets = SubnetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_network_gateways = VirtualNetworkGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_network_gateway_connections = VirtualNetworkGatewayConnectionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.local_network_gateways = LocalNetworkGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)
