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
from .operations_async import AvailableEndpointServicesOperations
from .operations_async import ExpressRouteCircuitAuthorizationsOperations
from .operations_async import ExpressRouteCircuitPeeringsOperations
from .operations_async import ExpressRouteCircuitsOperations
from .operations_async import ExpressRouteServiceProvidersOperations
from .operations_async import LoadBalancersOperations
from .operations_async import LoadBalancerBackendAddressPoolsOperations
from .operations_async import LoadBalancerFrontendIPConfigurationsOperations
from .operations_async import InboundNatRulesOperations
from .operations_async import LoadBalancerLoadBalancingRulesOperations
from .operations_async import LoadBalancerNetworkInterfacesOperations
from .operations_async import LoadBalancerProbesOperations
from .operations_async import NetworkInterfacesOperations
from .operations_async import NetworkInterfaceIPConfigurationsOperations
from .operations_async import NetworkInterfaceLoadBalancersOperations
from .operations_async import NetworkSecurityGroupsOperations
from .operations_async import SecurityRulesOperations
from .operations_async import DefaultSecurityRulesOperations
from .operations_async import NetworkWatchersOperations
from .operations_async import PacketCapturesOperations
from .operations_async import PublicIPAddressesOperations
from .operations_async import RouteFiltersOperations
from .operations_async import RouteFilterRulesOperations
from .operations_async import RouteTablesOperations
from .operations_async import RoutesOperations
from .operations_async import BgpServiceCommunitiesOperations
from .operations_async import UsagesOperations
from .operations_async import VirtualNetworksOperations
from .operations_async import SubnetsOperations
from .operations_async import VirtualNetworkPeeringsOperations
from .operations_async import VirtualNetworkGatewaysOperations
from .operations_async import VirtualNetworkGatewayConnectionsOperations
from .operations_async import LocalNetworkGatewaysOperations
from . import models


class NetworkManagementClientAsync(NetworkManagementClientOperationsMixin, SDKClientAsync):
    """Network Client

    :ivar config: Configuration for client.
    :vartype config: NetworkManagementClientConfiguration

    :ivar application_gateways: ApplicationGateways operations
    :vartype application_gateways: azure.mgmt.network.v2017_08_01.operations.ApplicationGatewaysOperations
    :ivar available_endpoint_services: AvailableEndpointServices operations
    :vartype available_endpoint_services: azure.mgmt.network.v2017_08_01.operations.AvailableEndpointServicesOperations
    :ivar express_route_circuit_authorizations: ExpressRouteCircuitAuthorizations operations
    :vartype express_route_circuit_authorizations: azure.mgmt.network.v2017_08_01.operations.ExpressRouteCircuitAuthorizationsOperations
    :ivar express_route_circuit_peerings: ExpressRouteCircuitPeerings operations
    :vartype express_route_circuit_peerings: azure.mgmt.network.v2017_08_01.operations.ExpressRouteCircuitPeeringsOperations
    :ivar express_route_circuits: ExpressRouteCircuits operations
    :vartype express_route_circuits: azure.mgmt.network.v2017_08_01.operations.ExpressRouteCircuitsOperations
    :ivar express_route_service_providers: ExpressRouteServiceProviders operations
    :vartype express_route_service_providers: azure.mgmt.network.v2017_08_01.operations.ExpressRouteServiceProvidersOperations
    :ivar load_balancers: LoadBalancers operations
    :vartype load_balancers: azure.mgmt.network.v2017_08_01.operations.LoadBalancersOperations
    :ivar load_balancer_backend_address_pools: LoadBalancerBackendAddressPools operations
    :vartype load_balancer_backend_address_pools: azure.mgmt.network.v2017_08_01.operations.LoadBalancerBackendAddressPoolsOperations
    :ivar load_balancer_frontend_ip_configurations: LoadBalancerFrontendIPConfigurations operations
    :vartype load_balancer_frontend_ip_configurations: azure.mgmt.network.v2017_08_01.operations.LoadBalancerFrontendIPConfigurationsOperations
    :ivar inbound_nat_rules: InboundNatRules operations
    :vartype inbound_nat_rules: azure.mgmt.network.v2017_08_01.operations.InboundNatRulesOperations
    :ivar load_balancer_load_balancing_rules: LoadBalancerLoadBalancingRules operations
    :vartype load_balancer_load_balancing_rules: azure.mgmt.network.v2017_08_01.operations.LoadBalancerLoadBalancingRulesOperations
    :ivar load_balancer_network_interfaces: LoadBalancerNetworkInterfaces operations
    :vartype load_balancer_network_interfaces: azure.mgmt.network.v2017_08_01.operations.LoadBalancerNetworkInterfacesOperations
    :ivar load_balancer_probes: LoadBalancerProbes operations
    :vartype load_balancer_probes: azure.mgmt.network.v2017_08_01.operations.LoadBalancerProbesOperations
    :ivar network_interfaces: NetworkInterfaces operations
    :vartype network_interfaces: azure.mgmt.network.v2017_08_01.operations.NetworkInterfacesOperations
    :ivar network_interface_ip_configurations: NetworkInterfaceIPConfigurations operations
    :vartype network_interface_ip_configurations: azure.mgmt.network.v2017_08_01.operations.NetworkInterfaceIPConfigurationsOperations
    :ivar network_interface_load_balancers: NetworkInterfaceLoadBalancers operations
    :vartype network_interface_load_balancers: azure.mgmt.network.v2017_08_01.operations.NetworkInterfaceLoadBalancersOperations
    :ivar network_security_groups: NetworkSecurityGroups operations
    :vartype network_security_groups: azure.mgmt.network.v2017_08_01.operations.NetworkSecurityGroupsOperations
    :ivar security_rules: SecurityRules operations
    :vartype security_rules: azure.mgmt.network.v2017_08_01.operations.SecurityRulesOperations
    :ivar default_security_rules: DefaultSecurityRules operations
    :vartype default_security_rules: azure.mgmt.network.v2017_08_01.operations.DefaultSecurityRulesOperations
    :ivar network_watchers: NetworkWatchers operations
    :vartype network_watchers: azure.mgmt.network.v2017_08_01.operations.NetworkWatchersOperations
    :ivar packet_captures: PacketCaptures operations
    :vartype packet_captures: azure.mgmt.network.v2017_08_01.operations.PacketCapturesOperations
    :ivar public_ip_addresses: PublicIPAddresses operations
    :vartype public_ip_addresses: azure.mgmt.network.v2017_08_01.operations.PublicIPAddressesOperations
    :ivar route_filters: RouteFilters operations
    :vartype route_filters: azure.mgmt.network.v2017_08_01.operations.RouteFiltersOperations
    :ivar route_filter_rules: RouteFilterRules operations
    :vartype route_filter_rules: azure.mgmt.network.v2017_08_01.operations.RouteFilterRulesOperations
    :ivar route_tables: RouteTables operations
    :vartype route_tables: azure.mgmt.network.v2017_08_01.operations.RouteTablesOperations
    :ivar routes: Routes operations
    :vartype routes: azure.mgmt.network.v2017_08_01.operations.RoutesOperations
    :ivar bgp_service_communities: BgpServiceCommunities operations
    :vartype bgp_service_communities: azure.mgmt.network.v2017_08_01.operations.BgpServiceCommunitiesOperations
    :ivar usages: Usages operations
    :vartype usages: azure.mgmt.network.v2017_08_01.operations.UsagesOperations
    :ivar virtual_networks: VirtualNetworks operations
    :vartype virtual_networks: azure.mgmt.network.v2017_08_01.operations.VirtualNetworksOperations
    :ivar subnets: Subnets operations
    :vartype subnets: azure.mgmt.network.v2017_08_01.operations.SubnetsOperations
    :ivar virtual_network_peerings: VirtualNetworkPeerings operations
    :vartype virtual_network_peerings: azure.mgmt.network.v2017_08_01.operations.VirtualNetworkPeeringsOperations
    :ivar virtual_network_gateways: VirtualNetworkGateways operations
    :vartype virtual_network_gateways: azure.mgmt.network.v2017_08_01.operations.VirtualNetworkGatewaysOperations
    :ivar virtual_network_gateway_connections: VirtualNetworkGatewayConnections operations
    :vartype virtual_network_gateway_connections: azure.mgmt.network.v2017_08_01.operations.VirtualNetworkGatewayConnectionsOperations
    :ivar local_network_gateways: LocalNetworkGateways operations
    :vartype local_network_gateways: azure.mgmt.network.v2017_08_01.operations.LocalNetworkGatewaysOperations

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
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.application_gateways = ApplicationGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.available_endpoint_services = AvailableEndpointServicesOperations(
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
        self.load_balancer_backend_address_pools = LoadBalancerBackendAddressPoolsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.load_balancer_frontend_ip_configurations = LoadBalancerFrontendIPConfigurationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.inbound_nat_rules = InboundNatRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.load_balancer_load_balancing_rules = LoadBalancerLoadBalancingRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.load_balancer_network_interfaces = LoadBalancerNetworkInterfacesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.load_balancer_probes = LoadBalancerProbesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_interfaces = NetworkInterfacesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_interface_ip_configurations = NetworkInterfaceIPConfigurationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_interface_load_balancers = NetworkInterfaceLoadBalancersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_security_groups = NetworkSecurityGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.security_rules = SecurityRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.default_security_rules = DefaultSecurityRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_watchers = NetworkWatchersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.packet_captures = PacketCapturesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.public_ip_addresses = PublicIPAddressesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.route_filters = RouteFiltersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.route_filter_rules = RouteFilterRulesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.route_tables = RouteTablesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.routes = RoutesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.bgp_service_communities = BgpServiceCommunitiesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.usages = UsagesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_networks = VirtualNetworksOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subnets = SubnetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_network_peerings = VirtualNetworkPeeringsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_network_gateways = VirtualNetworkGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.virtual_network_gateway_connections = VirtualNetworkGatewayConnectionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.local_network_gateways = LocalNetworkGatewaysOperations(
            self._client, self.config, self._serialize, self._deserialize)
