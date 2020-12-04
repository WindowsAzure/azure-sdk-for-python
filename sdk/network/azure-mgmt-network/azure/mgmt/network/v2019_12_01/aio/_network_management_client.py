# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import NetworkManagementClientConfiguration
from .operations import ApplicationGatewaysOperations
from .operations import ApplicationSecurityGroupsOperations
from .operations import AvailableDelegationsOperations
from .operations import AvailableResourceGroupDelegationsOperations
from .operations import AvailableServiceAliasesOperations
from .operations import AzureFirewallsOperations
from .operations import AzureFirewallFqdnTagsOperations
from .operations import BastionHostsOperations
from .operations import NetworkManagementClientOperationsMixin
from .operations import DdosCustomPoliciesOperations
from .operations import DdosProtectionPlansOperations
from .operations import AvailableEndpointServicesOperations
from .operations import ExpressRouteCircuitAuthorizationsOperations
from .operations import ExpressRouteCircuitPeeringsOperations
from .operations import ExpressRouteCircuitConnectionsOperations
from .operations import PeerExpressRouteCircuitConnectionsOperations
from .operations import ExpressRouteCircuitsOperations
from .operations import ExpressRouteServiceProvidersOperations
from .operations import ExpressRouteCrossConnectionsOperations
from .operations import ExpressRouteCrossConnectionPeeringsOperations
from .operations import ExpressRouteGatewaysOperations
from .operations import ExpressRouteConnectionsOperations
from .operations import ExpressRoutePortsLocationsOperations
from .operations import ExpressRoutePortsOperations
from .operations import ExpressRouteLinksOperations
from .operations import FirewallPoliciesOperations
from .operations import FirewallPolicyRuleGroupsOperations
from .operations import IpGroupsOperations
from .operations import LoadBalancersOperations
from .operations import LoadBalancerBackendAddressPoolsOperations
from .operations import LoadBalancerFrontendIPConfigurationsOperations
from .operations import InboundNatRulesOperations
from .operations import LoadBalancerLoadBalancingRulesOperations
from .operations import LoadBalancerOutboundRulesOperations
from .operations import LoadBalancerNetworkInterfacesOperations
from .operations import LoadBalancerProbesOperations
from .operations import NatGatewaysOperations
from .operations import NetworkInterfacesOperations
from .operations import NetworkInterfaceIPConfigurationsOperations
from .operations import NetworkInterfaceLoadBalancersOperations
from .operations import NetworkInterfaceTapConfigurationsOperations
from .operations import NetworkProfilesOperations
from .operations import NetworkSecurityGroupsOperations
from .operations import SecurityRulesOperations
from .operations import DefaultSecurityRulesOperations
from .operations import NetworkVirtualAppliancesOperations
from .operations import NetworkWatchersOperations
from .operations import PacketCapturesOperations
from .operations import ConnectionMonitorsOperations
from .operations import FlowLogsOperations
from .operations import Operations
from .operations import PrivateEndpointsOperations
from .operations import AvailablePrivateEndpointTypesOperations
from .operations import PrivateLinkServicesOperations
from .operations import PublicIPAddressesOperations
from .operations import PublicIPPrefixesOperations
from .operations import RouteFiltersOperations
from .operations import RouteFilterRulesOperations
from .operations import RouteTablesOperations
from .operations import RoutesOperations
from .operations import BgpServiceCommunitiesOperations
from .operations import ServiceEndpointPoliciesOperations
from .operations import ServiceEndpointPolicyDefinitionsOperations
from .operations import ServiceTagsOperations
from .operations import UsagesOperations
from .operations import VirtualNetworksOperations
from .operations import SubnetsOperations
from .operations import ResourceNavigationLinksOperations
from .operations import ServiceAssociationLinksOperations
from .operations import VirtualNetworkPeeringsOperations
from .operations import VirtualNetworkGatewaysOperations
from .operations import VirtualNetworkGatewayConnectionsOperations
from .operations import LocalNetworkGatewaysOperations
from .operations import VirtualNetworkTapsOperations
from .operations import VirtualRoutersOperations
from .operations import VirtualRouterPeeringsOperations
from .operations import VirtualWansOperations
from .operations import VpnSitesOperations
from .operations import VpnSiteLinksOperations
from .operations import VpnSitesConfigurationOperations
from .operations import VpnServerConfigurationsOperations
from .operations import VirtualHubsOperations
from .operations import HubVirtualNetworkConnectionsOperations
from .operations import VpnGatewaysOperations
from .operations import VpnConnectionsOperations
from .operations import VpnSiteLinkConnectionsOperations
from .operations import VpnLinkConnectionsOperations
from .operations import P2SVpnGatewaysOperations
from .operations import VpnServerConfigurationsAssociatedWithVirtualWanOperations
from .operations import VirtualHubRouteTableV2SOperations
from .operations import WebApplicationFirewallPoliciesOperations
from .. import models


class NetworkManagementClient(NetworkManagementClientOperationsMixin):
    """Network Client.

    :ivar application_gateways: ApplicationGatewaysOperations operations
    :vartype application_gateways: azure.mgmt.network.v2019_12_01.aio.operations.ApplicationGatewaysOperations
    :ivar application_security_groups: ApplicationSecurityGroupsOperations operations
    :vartype application_security_groups: azure.mgmt.network.v2019_12_01.aio.operations.ApplicationSecurityGroupsOperations
    :ivar available_delegations: AvailableDelegationsOperations operations
    :vartype available_delegations: azure.mgmt.network.v2019_12_01.aio.operations.AvailableDelegationsOperations
    :ivar available_resource_group_delegations: AvailableResourceGroupDelegationsOperations operations
    :vartype available_resource_group_delegations: azure.mgmt.network.v2019_12_01.aio.operations.AvailableResourceGroupDelegationsOperations
    :ivar available_service_aliases: AvailableServiceAliasesOperations operations
    :vartype available_service_aliases: azure.mgmt.network.v2019_12_01.aio.operations.AvailableServiceAliasesOperations
    :ivar azure_firewalls: AzureFirewallsOperations operations
    :vartype azure_firewalls: azure.mgmt.network.v2019_12_01.aio.operations.AzureFirewallsOperations
    :ivar azure_firewall_fqdn_tags: AzureFirewallFqdnTagsOperations operations
    :vartype azure_firewall_fqdn_tags: azure.mgmt.network.v2019_12_01.aio.operations.AzureFirewallFqdnTagsOperations
    :ivar bastion_hosts: BastionHostsOperations operations
    :vartype bastion_hosts: azure.mgmt.network.v2019_12_01.aio.operations.BastionHostsOperations
    :ivar ddos_custom_policies: DdosCustomPoliciesOperations operations
    :vartype ddos_custom_policies: azure.mgmt.network.v2019_12_01.aio.operations.DdosCustomPoliciesOperations
    :ivar ddos_protection_plans: DdosProtectionPlansOperations operations
    :vartype ddos_protection_plans: azure.mgmt.network.v2019_12_01.aio.operations.DdosProtectionPlansOperations
    :ivar available_endpoint_services: AvailableEndpointServicesOperations operations
    :vartype available_endpoint_services: azure.mgmt.network.v2019_12_01.aio.operations.AvailableEndpointServicesOperations
    :ivar express_route_circuit_authorizations: ExpressRouteCircuitAuthorizationsOperations operations
    :vartype express_route_circuit_authorizations: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteCircuitAuthorizationsOperations
    :ivar express_route_circuit_peerings: ExpressRouteCircuitPeeringsOperations operations
    :vartype express_route_circuit_peerings: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteCircuitPeeringsOperations
    :ivar express_route_circuit_connections: ExpressRouteCircuitConnectionsOperations operations
    :vartype express_route_circuit_connections: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteCircuitConnectionsOperations
    :ivar peer_express_route_circuit_connections: PeerExpressRouteCircuitConnectionsOperations operations
    :vartype peer_express_route_circuit_connections: azure.mgmt.network.v2019_12_01.aio.operations.PeerExpressRouteCircuitConnectionsOperations
    :ivar express_route_circuits: ExpressRouteCircuitsOperations operations
    :vartype express_route_circuits: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteCircuitsOperations
    :ivar express_route_service_providers: ExpressRouteServiceProvidersOperations operations
    :vartype express_route_service_providers: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteServiceProvidersOperations
    :ivar express_route_cross_connections: ExpressRouteCrossConnectionsOperations operations
    :vartype express_route_cross_connections: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteCrossConnectionsOperations
    :ivar express_route_cross_connection_peerings: ExpressRouteCrossConnectionPeeringsOperations operations
    :vartype express_route_cross_connection_peerings: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteCrossConnectionPeeringsOperations
    :ivar express_route_gateways: ExpressRouteGatewaysOperations operations
    :vartype express_route_gateways: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteGatewaysOperations
    :ivar express_route_connections: ExpressRouteConnectionsOperations operations
    :vartype express_route_connections: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteConnectionsOperations
    :ivar express_route_ports_locations: ExpressRoutePortsLocationsOperations operations
    :vartype express_route_ports_locations: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRoutePortsLocationsOperations
    :ivar express_route_ports: ExpressRoutePortsOperations operations
    :vartype express_route_ports: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRoutePortsOperations
    :ivar express_route_links: ExpressRouteLinksOperations operations
    :vartype express_route_links: azure.mgmt.network.v2019_12_01.aio.operations.ExpressRouteLinksOperations
    :ivar firewall_policies: FirewallPoliciesOperations operations
    :vartype firewall_policies: azure.mgmt.network.v2019_12_01.aio.operations.FirewallPoliciesOperations
    :ivar firewall_policy_rule_groups: FirewallPolicyRuleGroupsOperations operations
    :vartype firewall_policy_rule_groups: azure.mgmt.network.v2019_12_01.aio.operations.FirewallPolicyRuleGroupsOperations
    :ivar ip_groups: IpGroupsOperations operations
    :vartype ip_groups: azure.mgmt.network.v2019_12_01.aio.operations.IpGroupsOperations
    :ivar load_balancers: LoadBalancersOperations operations
    :vartype load_balancers: azure.mgmt.network.v2019_12_01.aio.operations.LoadBalancersOperations
    :ivar load_balancer_backend_address_pools: LoadBalancerBackendAddressPoolsOperations operations
    :vartype load_balancer_backend_address_pools: azure.mgmt.network.v2019_12_01.aio.operations.LoadBalancerBackendAddressPoolsOperations
    :ivar load_balancer_frontend_ip_configurations: LoadBalancerFrontendIPConfigurationsOperations operations
    :vartype load_balancer_frontend_ip_configurations: azure.mgmt.network.v2019_12_01.aio.operations.LoadBalancerFrontendIPConfigurationsOperations
    :ivar inbound_nat_rules: InboundNatRulesOperations operations
    :vartype inbound_nat_rules: azure.mgmt.network.v2019_12_01.aio.operations.InboundNatRulesOperations
    :ivar load_balancer_load_balancing_rules: LoadBalancerLoadBalancingRulesOperations operations
    :vartype load_balancer_load_balancing_rules: azure.mgmt.network.v2019_12_01.aio.operations.LoadBalancerLoadBalancingRulesOperations
    :ivar load_balancer_outbound_rules: LoadBalancerOutboundRulesOperations operations
    :vartype load_balancer_outbound_rules: azure.mgmt.network.v2019_12_01.aio.operations.LoadBalancerOutboundRulesOperations
    :ivar load_balancer_network_interfaces: LoadBalancerNetworkInterfacesOperations operations
    :vartype load_balancer_network_interfaces: azure.mgmt.network.v2019_12_01.aio.operations.LoadBalancerNetworkInterfacesOperations
    :ivar load_balancer_probes: LoadBalancerProbesOperations operations
    :vartype load_balancer_probes: azure.mgmt.network.v2019_12_01.aio.operations.LoadBalancerProbesOperations
    :ivar nat_gateways: NatGatewaysOperations operations
    :vartype nat_gateways: azure.mgmt.network.v2019_12_01.aio.operations.NatGatewaysOperations
    :ivar network_interfaces: NetworkInterfacesOperations operations
    :vartype network_interfaces: azure.mgmt.network.v2019_12_01.aio.operations.NetworkInterfacesOperations
    :ivar network_interface_ip_configurations: NetworkInterfaceIPConfigurationsOperations operations
    :vartype network_interface_ip_configurations: azure.mgmt.network.v2019_12_01.aio.operations.NetworkInterfaceIPConfigurationsOperations
    :ivar network_interface_load_balancers: NetworkInterfaceLoadBalancersOperations operations
    :vartype network_interface_load_balancers: azure.mgmt.network.v2019_12_01.aio.operations.NetworkInterfaceLoadBalancersOperations
    :ivar network_interface_tap_configurations: NetworkInterfaceTapConfigurationsOperations operations
    :vartype network_interface_tap_configurations: azure.mgmt.network.v2019_12_01.aio.operations.NetworkInterfaceTapConfigurationsOperations
    :ivar network_profiles: NetworkProfilesOperations operations
    :vartype network_profiles: azure.mgmt.network.v2019_12_01.aio.operations.NetworkProfilesOperations
    :ivar network_security_groups: NetworkSecurityGroupsOperations operations
    :vartype network_security_groups: azure.mgmt.network.v2019_12_01.aio.operations.NetworkSecurityGroupsOperations
    :ivar security_rules: SecurityRulesOperations operations
    :vartype security_rules: azure.mgmt.network.v2019_12_01.aio.operations.SecurityRulesOperations
    :ivar default_security_rules: DefaultSecurityRulesOperations operations
    :vartype default_security_rules: azure.mgmt.network.v2019_12_01.aio.operations.DefaultSecurityRulesOperations
    :ivar network_virtual_appliances: NetworkVirtualAppliancesOperations operations
    :vartype network_virtual_appliances: azure.mgmt.network.v2019_12_01.aio.operations.NetworkVirtualAppliancesOperations
    :ivar network_watchers: NetworkWatchersOperations operations
    :vartype network_watchers: azure.mgmt.network.v2019_12_01.aio.operations.NetworkWatchersOperations
    :ivar packet_captures: PacketCapturesOperations operations
    :vartype packet_captures: azure.mgmt.network.v2019_12_01.aio.operations.PacketCapturesOperations
    :ivar connection_monitors: ConnectionMonitorsOperations operations
    :vartype connection_monitors: azure.mgmt.network.v2019_12_01.aio.operations.ConnectionMonitorsOperations
    :ivar flow_logs: FlowLogsOperations operations
    :vartype flow_logs: azure.mgmt.network.v2019_12_01.aio.operations.FlowLogsOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.network.v2019_12_01.aio.operations.Operations
    :ivar private_endpoints: PrivateEndpointsOperations operations
    :vartype private_endpoints: azure.mgmt.network.v2019_12_01.aio.operations.PrivateEndpointsOperations
    :ivar available_private_endpoint_types: AvailablePrivateEndpointTypesOperations operations
    :vartype available_private_endpoint_types: azure.mgmt.network.v2019_12_01.aio.operations.AvailablePrivateEndpointTypesOperations
    :ivar private_link_services: PrivateLinkServicesOperations operations
    :vartype private_link_services: azure.mgmt.network.v2019_12_01.aio.operations.PrivateLinkServicesOperations
    :ivar public_ip_addresses: PublicIPAddressesOperations operations
    :vartype public_ip_addresses: azure.mgmt.network.v2019_12_01.aio.operations.PublicIPAddressesOperations
    :ivar public_ip_prefixes: PublicIPPrefixesOperations operations
    :vartype public_ip_prefixes: azure.mgmt.network.v2019_12_01.aio.operations.PublicIPPrefixesOperations
    :ivar route_filters: RouteFiltersOperations operations
    :vartype route_filters: azure.mgmt.network.v2019_12_01.aio.operations.RouteFiltersOperations
    :ivar route_filter_rules: RouteFilterRulesOperations operations
    :vartype route_filter_rules: azure.mgmt.network.v2019_12_01.aio.operations.RouteFilterRulesOperations
    :ivar route_tables: RouteTablesOperations operations
    :vartype route_tables: azure.mgmt.network.v2019_12_01.aio.operations.RouteTablesOperations
    :ivar routes: RoutesOperations operations
    :vartype routes: azure.mgmt.network.v2019_12_01.aio.operations.RoutesOperations
    :ivar bgp_service_communities: BgpServiceCommunitiesOperations operations
    :vartype bgp_service_communities: azure.mgmt.network.v2019_12_01.aio.operations.BgpServiceCommunitiesOperations
    :ivar service_endpoint_policies: ServiceEndpointPoliciesOperations operations
    :vartype service_endpoint_policies: azure.mgmt.network.v2019_12_01.aio.operations.ServiceEndpointPoliciesOperations
    :ivar service_endpoint_policy_definitions: ServiceEndpointPolicyDefinitionsOperations operations
    :vartype service_endpoint_policy_definitions: azure.mgmt.network.v2019_12_01.aio.operations.ServiceEndpointPolicyDefinitionsOperations
    :ivar service_tags: ServiceTagsOperations operations
    :vartype service_tags: azure.mgmt.network.v2019_12_01.aio.operations.ServiceTagsOperations
    :ivar usages: UsagesOperations operations
    :vartype usages: azure.mgmt.network.v2019_12_01.aio.operations.UsagesOperations
    :ivar virtual_networks: VirtualNetworksOperations operations
    :vartype virtual_networks: azure.mgmt.network.v2019_12_01.aio.operations.VirtualNetworksOperations
    :ivar subnets: SubnetsOperations operations
    :vartype subnets: azure.mgmt.network.v2019_12_01.aio.operations.SubnetsOperations
    :ivar resource_navigation_links: ResourceNavigationLinksOperations operations
    :vartype resource_navigation_links: azure.mgmt.network.v2019_12_01.aio.operations.ResourceNavigationLinksOperations
    :ivar service_association_links: ServiceAssociationLinksOperations operations
    :vartype service_association_links: azure.mgmt.network.v2019_12_01.aio.operations.ServiceAssociationLinksOperations
    :ivar virtual_network_peerings: VirtualNetworkPeeringsOperations operations
    :vartype virtual_network_peerings: azure.mgmt.network.v2019_12_01.aio.operations.VirtualNetworkPeeringsOperations
    :ivar virtual_network_gateways: VirtualNetworkGatewaysOperations operations
    :vartype virtual_network_gateways: azure.mgmt.network.v2019_12_01.aio.operations.VirtualNetworkGatewaysOperations
    :ivar virtual_network_gateway_connections: VirtualNetworkGatewayConnectionsOperations operations
    :vartype virtual_network_gateway_connections: azure.mgmt.network.v2019_12_01.aio.operations.VirtualNetworkGatewayConnectionsOperations
    :ivar local_network_gateways: LocalNetworkGatewaysOperations operations
    :vartype local_network_gateways: azure.mgmt.network.v2019_12_01.aio.operations.LocalNetworkGatewaysOperations
    :ivar virtual_network_taps: VirtualNetworkTapsOperations operations
    :vartype virtual_network_taps: azure.mgmt.network.v2019_12_01.aio.operations.VirtualNetworkTapsOperations
    :ivar virtual_routers: VirtualRoutersOperations operations
    :vartype virtual_routers: azure.mgmt.network.v2019_12_01.aio.operations.VirtualRoutersOperations
    :ivar virtual_router_peerings: VirtualRouterPeeringsOperations operations
    :vartype virtual_router_peerings: azure.mgmt.network.v2019_12_01.aio.operations.VirtualRouterPeeringsOperations
    :ivar virtual_wans: VirtualWansOperations operations
    :vartype virtual_wans: azure.mgmt.network.v2019_12_01.aio.operations.VirtualWansOperations
    :ivar vpn_sites: VpnSitesOperations operations
    :vartype vpn_sites: azure.mgmt.network.v2019_12_01.aio.operations.VpnSitesOperations
    :ivar vpn_site_links: VpnSiteLinksOperations operations
    :vartype vpn_site_links: azure.mgmt.network.v2019_12_01.aio.operations.VpnSiteLinksOperations
    :ivar vpn_sites_configuration: VpnSitesConfigurationOperations operations
    :vartype vpn_sites_configuration: azure.mgmt.network.v2019_12_01.aio.operations.VpnSitesConfigurationOperations
    :ivar vpn_server_configurations: VpnServerConfigurationsOperations operations
    :vartype vpn_server_configurations: azure.mgmt.network.v2019_12_01.aio.operations.VpnServerConfigurationsOperations
    :ivar virtual_hubs: VirtualHubsOperations operations
    :vartype virtual_hubs: azure.mgmt.network.v2019_12_01.aio.operations.VirtualHubsOperations
    :ivar hub_virtual_network_connections: HubVirtualNetworkConnectionsOperations operations
    :vartype hub_virtual_network_connections: azure.mgmt.network.v2019_12_01.aio.operations.HubVirtualNetworkConnectionsOperations
    :ivar vpn_gateways: VpnGatewaysOperations operations
    :vartype vpn_gateways: azure.mgmt.network.v2019_12_01.aio.operations.VpnGatewaysOperations
    :ivar vpn_connections: VpnConnectionsOperations operations
    :vartype vpn_connections: azure.mgmt.network.v2019_12_01.aio.operations.VpnConnectionsOperations
    :ivar vpn_site_link_connections: VpnSiteLinkConnectionsOperations operations
    :vartype vpn_site_link_connections: azure.mgmt.network.v2019_12_01.aio.operations.VpnSiteLinkConnectionsOperations
    :ivar vpn_link_connections: VpnLinkConnectionsOperations operations
    :vartype vpn_link_connections: azure.mgmt.network.v2019_12_01.aio.operations.VpnLinkConnectionsOperations
    :ivar p2_svpn_gateways: P2SVpnGatewaysOperations operations
    :vartype p2_svpn_gateways: azure.mgmt.network.v2019_12_01.aio.operations.P2SVpnGatewaysOperations
    :ivar vpn_server_configurations_associated_with_virtual_wan: VpnServerConfigurationsAssociatedWithVirtualWanOperations operations
    :vartype vpn_server_configurations_associated_with_virtual_wan: azure.mgmt.network.v2019_12_01.aio.operations.VpnServerConfigurationsAssociatedWithVirtualWanOperations
    :ivar virtual_hub_route_table_v2_s: VirtualHubRouteTableV2SOperations operations
    :vartype virtual_hub_route_table_v2_s: azure.mgmt.network.v2019_12_01.aio.operations.VirtualHubRouteTableV2SOperations
    :ivar web_application_firewall_policies: WebApplicationFirewallPoliciesOperations operations
    :vartype web_application_firewall_policies: azure.mgmt.network.v2019_12_01.aio.operations.WebApplicationFirewallPoliciesOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: The subscription credentials which uniquely identify the Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = NetworkManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.application_gateways = ApplicationGatewaysOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.application_security_groups = ApplicationSecurityGroupsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.available_delegations = AvailableDelegationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.available_resource_group_delegations = AvailableResourceGroupDelegationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.available_service_aliases = AvailableServiceAliasesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.azure_firewalls = AzureFirewallsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.azure_firewall_fqdn_tags = AzureFirewallFqdnTagsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.bastion_hosts = BastionHostsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.ddos_custom_policies = DdosCustomPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.ddos_protection_plans = DdosProtectionPlansOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.available_endpoint_services = AvailableEndpointServicesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_circuit_authorizations = ExpressRouteCircuitAuthorizationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_circuit_peerings = ExpressRouteCircuitPeeringsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_circuit_connections = ExpressRouteCircuitConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.peer_express_route_circuit_connections = PeerExpressRouteCircuitConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_circuits = ExpressRouteCircuitsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_service_providers = ExpressRouteServiceProvidersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_cross_connections = ExpressRouteCrossConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_cross_connection_peerings = ExpressRouteCrossConnectionPeeringsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_gateways = ExpressRouteGatewaysOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_connections = ExpressRouteConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_ports_locations = ExpressRoutePortsLocationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_ports = ExpressRoutePortsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.express_route_links = ExpressRouteLinksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.firewall_policies = FirewallPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.firewall_policy_rule_groups = FirewallPolicyRuleGroupsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.ip_groups = IpGroupsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.load_balancers = LoadBalancersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.load_balancer_backend_address_pools = LoadBalancerBackendAddressPoolsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.load_balancer_frontend_ip_configurations = LoadBalancerFrontendIPConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.inbound_nat_rules = InboundNatRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.load_balancer_load_balancing_rules = LoadBalancerLoadBalancingRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.load_balancer_outbound_rules = LoadBalancerOutboundRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.load_balancer_network_interfaces = LoadBalancerNetworkInterfacesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.load_balancer_probes = LoadBalancerProbesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.nat_gateways = NatGatewaysOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.network_interfaces = NetworkInterfacesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.network_interface_ip_configurations = NetworkInterfaceIPConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.network_interface_load_balancers = NetworkInterfaceLoadBalancersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.network_interface_tap_configurations = NetworkInterfaceTapConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.network_profiles = NetworkProfilesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.network_security_groups = NetworkSecurityGroupsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.security_rules = SecurityRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.default_security_rules = DefaultSecurityRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.network_virtual_appliances = NetworkVirtualAppliancesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.network_watchers = NetworkWatchersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.packet_captures = PacketCapturesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.connection_monitors = ConnectionMonitorsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.flow_logs = FlowLogsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_endpoints = PrivateEndpointsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.available_private_endpoint_types = AvailablePrivateEndpointTypesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_link_services = PrivateLinkServicesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.public_ip_addresses = PublicIPAddressesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.public_ip_prefixes = PublicIPPrefixesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.route_filters = RouteFiltersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.route_filter_rules = RouteFilterRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.route_tables = RouteTablesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.routes = RoutesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.bgp_service_communities = BgpServiceCommunitiesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_endpoint_policies = ServiceEndpointPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_endpoint_policy_definitions = ServiceEndpointPolicyDefinitionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_tags = ServiceTagsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.usages = UsagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_networks = VirtualNetworksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.subnets = SubnetsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.resource_navigation_links = ResourceNavigationLinksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.service_association_links = ServiceAssociationLinksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_network_peerings = VirtualNetworkPeeringsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_network_gateways = VirtualNetworkGatewaysOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_network_gateway_connections = VirtualNetworkGatewayConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.local_network_gateways = LocalNetworkGatewaysOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_network_taps = VirtualNetworkTapsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_routers = VirtualRoutersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_router_peerings = VirtualRouterPeeringsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_wans = VirtualWansOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_sites = VpnSitesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_site_links = VpnSiteLinksOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_sites_configuration = VpnSitesConfigurationOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_server_configurations = VpnServerConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_hubs = VirtualHubsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.hub_virtual_network_connections = HubVirtualNetworkConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_gateways = VpnGatewaysOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_connections = VpnConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_site_link_connections = VpnSiteLinkConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_link_connections = VpnLinkConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.p2_svpn_gateways = P2SVpnGatewaysOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.vpn_server_configurations_associated_with_virtual_wan = VpnServerConfigurationsAssociatedWithVirtualWanOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_hub_route_table_v2_s = VirtualHubRouteTableV2SOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.web_application_firewall_policies = WebApplicationFirewallPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "NetworkManagementClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
