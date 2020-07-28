# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum

class Access(str, Enum):
    """Access to be allowed or denied.
    """

    allow = "Allow"
    deny = "Deny"

class ApplicationGatewayBackendHealthServerHealth(str, Enum):
    """Health of backend server.
    """

    unknown = "Unknown"
    up = "Up"
    down = "Down"
    partial = "Partial"
    draining = "Draining"

class ApplicationGatewayCookieBasedAffinity(str, Enum):
    """Cookie based affinity.
    """

    enabled = "Enabled"
    disabled = "Disabled"

class ApplicationGatewayCustomErrorStatusCode(str, Enum):
    """Status code of the application gateway customer error.
    """

    http_status403 = "HttpStatus403"
    http_status502 = "HttpStatus502"

class ApplicationGatewayFirewallMode(str, Enum):
    """Web application firewall mode.
    """

    detection = "Detection"
    prevention = "Prevention"

class ApplicationGatewayOperationalState(str, Enum):
    """Operational state of the application gateway resource.
    """

    stopped = "Stopped"
    starting = "Starting"
    running = "Running"
    stopping = "Stopping"

class ApplicationGatewayProtocol(str, Enum):
    """Application Gateway protocol.
    """

    http = "Http"
    https = "Https"

class ApplicationGatewayRedirectType(str, Enum):
    """Redirect type enum.
    """

    permanent = "Permanent"
    found = "Found"
    see_other = "SeeOther"
    temporary = "Temporary"

class ApplicationGatewayRequestRoutingRuleType(str, Enum):
    """Rule type.
    """

    basic = "Basic"
    path_based_routing = "PathBasedRouting"

class ApplicationGatewaySkuName(str, Enum):
    """Name of an application gateway SKU.
    """

    standard_small = "Standard_Small"
    standard_medium = "Standard_Medium"
    standard_large = "Standard_Large"
    waf_medium = "WAF_Medium"
    waf_large = "WAF_Large"
    standard_v2 = "Standard_v2"
    waf_v2 = "WAF_v2"

class ApplicationGatewaySslCipherSuite(str, Enum):
    """Ssl cipher suites enums.
    """

    tls_ecdhe_rsa_with_aes256_cbc_sha384 = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    tls_ecdhe_rsa_with_aes128_cbc_sha256 = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
    tls_ecdhe_rsa_with_aes256_cbc_sha = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    tls_ecdhe_rsa_with_aes128_cbc_sha = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    tls_dhe_rsa_with_aes256_gcm_sha384 = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
    tls_dhe_rsa_with_aes128_gcm_sha256 = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
    tls_dhe_rsa_with_aes256_cbc_sha = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
    tls_dhe_rsa_with_aes128_cbc_sha = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
    tls_rsa_with_aes256_gcm_sha384 = "TLS_RSA_WITH_AES_256_GCM_SHA384"
    tls_rsa_with_aes128_gcm_sha256 = "TLS_RSA_WITH_AES_128_GCM_SHA256"
    tls_rsa_with_aes256_cbc_sha256 = "TLS_RSA_WITH_AES_256_CBC_SHA256"
    tls_rsa_with_aes128_cbc_sha256 = "TLS_RSA_WITH_AES_128_CBC_SHA256"
    tls_rsa_with_aes256_cbc_sha = "TLS_RSA_WITH_AES_256_CBC_SHA"
    tls_rsa_with_aes128_cbc_sha = "TLS_RSA_WITH_AES_128_CBC_SHA"
    tls_ecdhe_ecdsa_with_aes256_gcm_sha384 = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    tls_ecdhe_ecdsa_with_aes128_gcm_sha256 = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    tls_ecdhe_ecdsa_with_aes256_cbc_sha384 = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
    tls_ecdhe_ecdsa_with_aes128_cbc_sha256 = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
    tls_ecdhe_ecdsa_with_aes256_cbc_sha = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    tls_ecdhe_ecdsa_with_aes128_cbc_sha = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    tls_dhe_dss_with_aes256_cbc_sha256 = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
    tls_dhe_dss_with_aes128_cbc_sha256 = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
    tls_dhe_dss_with_aes256_cbc_sha = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
    tls_dhe_dss_with_aes128_cbc_sha = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
    tls_rsa_with3_des_ede_cbc_sha = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    tls_dhe_dss_with3_des_ede_cbc_sha = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
    tls_ecdhe_rsa_with_aes128_gcm_sha256 = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    tls_ecdhe_rsa_with_aes256_gcm_sha384 = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"

class ApplicationGatewaySslPolicyName(str, Enum):
    """Ssl predefined policy name enums.
    """

    app_gw_ssl_policy20150501 = "AppGwSslPolicy20150501"
    app_gw_ssl_policy20170401 = "AppGwSslPolicy20170401"
    app_gw_ssl_policy20170401_s = "AppGwSslPolicy20170401S"

class ApplicationGatewaySslPolicyType(str, Enum):
    """Type of Ssl Policy.
    """

    predefined = "Predefined"
    custom = "Custom"

class ApplicationGatewaySslProtocol(str, Enum):
    """Ssl protocol enums.
    """

    tl_sv1_0 = "TLSv1_0"
    tl_sv1_1 = "TLSv1_1"
    tl_sv1_2 = "TLSv1_2"

class ApplicationGatewayTier(str, Enum):
    """Tier of an application gateway.
    """

    standard = "Standard"
    waf = "WAF"
    standard_v2 = "Standard_v2"
    waf_v2 = "WAF_v2"

class AssociationType(str, Enum):
    """The association type of the child resource to the parent resource.
    """

    associated = "Associated"
    contains = "Contains"

class AuthenticationMethod(str, Enum):
    """VPN client authentication method.
    """

    eaptls = "EAPTLS"
    eapmscha_pv2 = "EAPMSCHAPv2"

class AuthorizationUseStatus(str, Enum):
    """The authorization use status.
    """

    available = "Available"
    in_use = "InUse"

class AzureFirewallApplicationRuleProtocolType(str, Enum):
    """The protocol type of a Application Rule resource.
    """

    http = "Http"
    https = "Https"
    mssql = "Mssql"

class AzureFirewallNatRCActionType(str, Enum):
    """The action type of a NAT rule collection.
    """

    snat = "Snat"
    dnat = "Dnat"

class AzureFirewallNetworkRuleProtocol(str, Enum):
    """The protocol of a Network Rule resource.
    """

    tcp = "TCP"
    udp = "UDP"
    any = "Any"
    icmp = "ICMP"

class AzureFirewallRCActionType(str, Enum):
    """The action type of a rule collection.
    """

    allow = "Allow"
    deny = "Deny"

class AzureFirewallThreatIntelMode(str, Enum):
    """The operation mode for Threat Intel.
    """

    alert = "Alert"
    deny = "Deny"
    off = "Off"

class BgpPeerState(str, Enum):
    """The BGP peer state.
    """

    unknown = "Unknown"
    stopped = "Stopped"
    idle = "Idle"
    connecting = "Connecting"
    connected = "Connected"

class CircuitConnectionStatus(str, Enum):
    """Express Route Circuit connection state.
    """

    connected = "Connected"
    connecting = "Connecting"
    disconnected = "Disconnected"

class ConnectionMonitorSourceStatus(str, Enum):
    """Status of connection monitor source.
    """

    unknown = "Unknown"
    active = "Active"
    inactive = "Inactive"

class ConnectionState(str, Enum):
    """The connection state.
    """

    reachable = "Reachable"
    unreachable = "Unreachable"
    unknown = "Unknown"

class ConnectionStatus(str, Enum):
    """The connection status.
    """

    unknown = "Unknown"
    connected = "Connected"
    disconnected = "Disconnected"
    degraded = "Degraded"

class DdosCustomPolicyProtocol(str, Enum):
    """The protocol for which the DDoS protection policy is being customized.
    """

    tcp = "Tcp"
    udp = "Udp"
    syn = "Syn"

class DdosCustomPolicyTriggerSensitivityOverride(str, Enum):
    """The customized DDoS protection trigger rate sensitivity degrees. High: Trigger rate set with
    most sensitivity w.r.t. normal traffic. Default: Trigger rate set with moderate sensitivity
    w.r.t. normal traffic. Low: Trigger rate set with less sensitivity w.r.t. normal traffic.
    Relaxed: Trigger rate set with least sensitivity w.r.t. normal traffic.
    """

    relaxed = "Relaxed"
    low = "Low"
    default = "Default"
    high = "High"

class DdosSettingsProtectionCoverage(str, Enum):
    """The DDoS protection policy customizability of the public IP. Only standard coverage will have
    the ability to be customized.
    """

    basic = "Basic"
    standard = "Standard"

class DhGroup(str, Enum):
    """The DH Groups used in IKE Phase 1 for initial SA.
    """

    none = "None"
    dh_group1 = "DHGroup1"
    dh_group2 = "DHGroup2"
    dh_group14 = "DHGroup14"
    dh_group2048 = "DHGroup2048"
    ecp256 = "ECP256"
    ecp384 = "ECP384"
    dh_group24 = "DHGroup24"

class Direction(str, Enum):
    """The direction of the traffic.
    """

    inbound = "Inbound"
    outbound = "Outbound"

class EffectiveRouteSource(str, Enum):
    """Who created the route.
    """

    unknown = "Unknown"
    user = "User"
    virtual_network_gateway = "VirtualNetworkGateway"
    default = "Default"

class EffectiveRouteState(str, Enum):
    """The value of effective route.
    """

    active = "Active"
    invalid = "Invalid"

class EffectiveSecurityRuleProtocol(str, Enum):
    """The network protocol this rule applies to.
    """

    tcp = "Tcp"
    udp = "Udp"
    all = "All"

class EvaluationState(str, Enum):
    """Connectivity analysis evaluation state.
    """

    not_started = "NotStarted"
    in_progress = "InProgress"
    completed = "Completed"

class ExpressRouteCircuitPeeringAdvertisedPublicPrefixState(str, Enum):
    """The advertised public prefix state of the Peering resource.
    """

    not_configured = "NotConfigured"
    configuring = "Configuring"
    configured = "Configured"
    validation_needed = "ValidationNeeded"

class ExpressRouteCircuitPeeringState(str, Enum):
    """The state of peering.
    """

    disabled = "Disabled"
    enabled = "Enabled"

class ExpressRouteCircuitSkuFamily(str, Enum):
    """The family of the SKU.
    """

    unlimited_data = "UnlimitedData"
    metered_data = "MeteredData"

class ExpressRouteCircuitSkuTier(str, Enum):
    """The tier of the SKU.
    """

    standard = "Standard"
    premium = "Premium"
    basic = "Basic"
    local = "Local"

class ExpressRouteLinkAdminState(str, Enum):
    """Administrative state of the physical port.
    """

    enabled = "Enabled"
    disabled = "Disabled"

class ExpressRouteLinkConnectorType(str, Enum):
    """Physical fiber port type.
    """

    lc = "LC"
    sc = "SC"

class ExpressRouteLinkMacSecCipher(str, Enum):
    """Mac security cipher.
    """

    gcm_aes128 = "gcm-aes-128"
    gcm_aes256 = "gcm-aes-256"

class ExpressRoutePeeringState(str, Enum):
    """The state of peering.
    """

    disabled = "Disabled"
    enabled = "Enabled"

class ExpressRoutePeeringType(str, Enum):
    """The peering type.
    """

    azure_public_peering = "AzurePublicPeering"
    azure_private_peering = "AzurePrivatePeering"
    microsoft_peering = "MicrosoftPeering"

class ExpressRoutePortsEncapsulation(str, Enum):
    """Encapsulation method on physical ports.
    """

    dot1_q = "Dot1Q"
    qin_q = "QinQ"

class FirewallPolicyFilterRuleActionType(str, Enum):
    """The action type of a rule.
    """

    allow = "Allow"
    deny = "Deny"
    alert = "Alert "

class FirewallPolicyNatRuleActionType(str, Enum):
    """The action type of a rule.
    """

    dnat = "DNAT"
    snat = "SNAT"

class FirewallPolicyRuleConditionApplicationProtocolType(str, Enum):
    """The application protocol type of a Rule condition.
    """

    http = "Http"
    https = "Https"

class FirewallPolicyRuleConditionNetworkProtocol(str, Enum):
    """The Network protocol of a Rule condition.
    """

    tcp = "TCP"
    udp = "UDP"
    any = "Any"
    icmp = "ICMP"

class FirewallPolicyRuleConditionType(str, Enum):
    """Rule Condition Type.
    """

    application_rule_condition = "ApplicationRuleCondition"
    network_rule_condition = "NetworkRuleCondition"

class FirewallPolicyRuleType(str, Enum):
    """The type of the rule.
    """

    firewall_policy_nat_rule = "FirewallPolicyNatRule"
    firewall_policy_filter_rule = "FirewallPolicyFilterRule"

class HubVirtualNetworkConnectionStatus(str, Enum):
    """The current state of the VirtualHub to vnet connection.
    """

    unknown = "Unknown"
    connecting = "Connecting"
    connected = "Connected"
    not_connected = "NotConnected"

class IkeEncryption(str, Enum):
    """The IKE encryption algorithm (IKE phase 2).
    """

    des = "DES"
    des3 = "DES3"
    aes128 = "AES128"
    aes192 = "AES192"
    aes256 = "AES256"
    gcmaes256 = "GCMAES256"
    gcmaes128 = "GCMAES128"

class IkeIntegrity(str, Enum):
    """The IKE integrity algorithm (IKE phase 2).
    """

    md5 = "MD5"
    sha1 = "SHA1"
    sha256 = "SHA256"
    sha384 = "SHA384"
    gcmaes256 = "GCMAES256"
    gcmaes128 = "GCMAES128"

class IPAllocationMethod(str, Enum):
    """IP address allocation method.
    """

    static = "Static"
    dynamic = "Dynamic"

class IpFlowProtocol(str, Enum):
    """Protocol to be verified on.
    """

    tcp = "TCP"
    udp = "UDP"

class IpsecEncryption(str, Enum):
    """The IPSec encryption algorithm (IKE phase 1).
    """

    none = "None"
    des = "DES"
    des3 = "DES3"
    aes128 = "AES128"
    aes192 = "AES192"
    aes256 = "AES256"
    gcmaes128 = "GCMAES128"
    gcmaes192 = "GCMAES192"
    gcmaes256 = "GCMAES256"

class IpsecIntegrity(str, Enum):
    """The IPSec integrity algorithm (IKE phase 1).
    """

    md5 = "MD5"
    sha1 = "SHA1"
    sha256 = "SHA256"
    gcmaes128 = "GCMAES128"
    gcmaes192 = "GCMAES192"
    gcmaes256 = "GCMAES256"

class IPVersion(str, Enum):
    """IP address version.
    """

    i_pv4 = "IPv4"
    i_pv6 = "IPv6"

class IssueType(str, Enum):
    """The type of issue.
    """

    unknown = "Unknown"
    agent_stopped = "AgentStopped"
    guest_firewall = "GuestFirewall"
    dns_resolution = "DnsResolution"
    socket_bind = "SocketBind"
    network_security_rule = "NetworkSecurityRule"
    user_defined_route = "UserDefinedRoute"
    port_throttled = "PortThrottled"
    platform = "Platform"

class LoadBalancerOutboundRuleProtocol(str, Enum):
    """The protocol for the outbound rule in load balancer.
    """

    tcp = "Tcp"
    udp = "Udp"
    all = "All"

class LoadBalancerSkuName(str, Enum):
    """Name of a load balancer SKU.
    """

    basic = "Basic"
    standard = "Standard"

class LoadDistribution(str, Enum):
    """The load distribution policy for this rule.
    """

    default = "Default"
    source_ip = "SourceIP"
    source_ip_protocol = "SourceIPProtocol"

class NetworkOperationStatus(str, Enum):
    """Status of the Azure async operation.
    """

    in_progress = "InProgress"
    succeeded = "Succeeded"
    failed = "Failed"

class NextHopType(str, Enum):
    """Next hop type.
    """

    internet = "Internet"
    virtual_appliance = "VirtualAppliance"
    virtual_network_gateway = "VirtualNetworkGateway"
    vnet_local = "VnetLocal"
    hyper_net_gateway = "HyperNetGateway"
    none = "None"

class OfficeTrafficCategory(str, Enum):
    """The office traffic category.
    """

    optimize = "Optimize"
    optimize_and_allow = "OptimizeAndAllow"
    all = "All"
    none = "None"

class Origin(str, Enum):
    """The origin of the issue.
    """

    local = "Local"
    inbound = "Inbound"
    outbound = "Outbound"

class PcError(str, Enum):

    internal_error = "InternalError"
    agent_stopped = "AgentStopped"
    capture_failed = "CaptureFailed"
    local_file_failed = "LocalFileFailed"
    storage_failed = "StorageFailed"

class PcProtocol(str, Enum):
    """Protocol to be filtered on.
    """

    tcp = "TCP"
    udp = "UDP"
    any = "Any"

class PcStatus(str, Enum):
    """The status of the packet capture session.
    """

    not_started = "NotStarted"
    running = "Running"
    stopped = "Stopped"
    error = "Error"
    unknown = "Unknown"

class PfsGroup(str, Enum):
    """The Pfs Groups used in IKE Phase 2 for new child SA.
    """

    none = "None"
    pfs1 = "PFS1"
    pfs2 = "PFS2"
    pfs2048 = "PFS2048"
    ecp256 = "ECP256"
    ecp384 = "ECP384"
    pfs24 = "PFS24"
    pfs14 = "PFS14"
    pfsmm = "PFSMM"

class ProbeProtocol(str, Enum):
    """The protocol of the end point. If 'Tcp' is specified, a received ACK is required for the probe
    to be successful. If 'Http' or 'Https' is specified, a 200 OK response from the specifies URI
    is required for the probe to be successful.
    """

    http = "Http"
    tcp = "Tcp"
    https = "Https"

class ProcessorArchitecture(str, Enum):
    """VPN client Processor Architecture.
    """

    amd64 = "Amd64"
    x86 = "X86"

class Protocol(str, Enum):
    """Network protocol.
    """

    tcp = "Tcp"
    http = "Http"
    https = "Https"
    icmp = "Icmp"

class ProvisioningState(str, Enum):
    """The current provisioning state.
    """

    succeeded = "Succeeded"
    updating = "Updating"
    deleting = "Deleting"
    failed = "Failed"

class PublicIPAddressSkuName(str, Enum):
    """Name of a public IP address SKU.
    """

    basic = "Basic"
    standard = "Standard"

class ResourceIdentityType(str, Enum):
    """The type of identity used for the resource. The type 'SystemAssigned, UserAssigned' includes
    both an implicitly created identity and a set of user assigned identities. The type 'None' will
    remove any identities from the virtual machine.
    """

    system_assigned = "SystemAssigned"
    user_assigned = "UserAssigned"
    system_assigned_user_assigned = "SystemAssigned, UserAssigned"
    none = "None"

class RouteNextHopType(str, Enum):
    """The type of Azure hop the packet should be sent to.
    """

    virtual_network_gateway = "VirtualNetworkGateway"
    vnet_local = "VnetLocal"
    internet = "Internet"
    virtual_appliance = "VirtualAppliance"
    none = "None"

class SecurityRuleAccess(str, Enum):
    """Whether network traffic is allowed or denied.
    """

    allow = "Allow"
    deny = "Deny"

class SecurityRuleDirection(str, Enum):
    """The direction of the rule. The direction specifies if rule will be evaluated on incoming or
    outgoing traffic.
    """

    inbound = "Inbound"
    outbound = "Outbound"

class SecurityRuleProtocol(str, Enum):
    """Network protocol this rule applies to.
    """

    tcp = "Tcp"
    udp = "Udp"
    icmp = "Icmp"
    esp = "Esp"
    asterisk = "*"

class ServiceProviderProvisioningState(str, Enum):
    """The ServiceProviderProvisioningState state of the resource.
    """

    not_provisioned = "NotProvisioned"
    provisioning = "Provisioning"
    provisioned = "Provisioned"
    deprovisioning = "Deprovisioning"

class Severity(str, Enum):
    """The severity of the issue.
    """

    error = "Error"
    warning = "Warning"

class TransportProtocol(str, Enum):
    """The transport protocol for the endpoint.
    """

    udp = "Udp"
    tcp = "Tcp"
    all = "All"

class TunnelConnectionStatus(str, Enum):
    """The current state of the tunnel.
    """

    unknown = "Unknown"
    connecting = "Connecting"
    connected = "Connected"
    not_connected = "NotConnected"

class VerbosityLevel(str, Enum):
    """Verbosity level.
    """

    normal = "Normal"
    minimum = "Minimum"
    full = "Full"

class VirtualNetworkGatewayConnectionProtocol(str, Enum):
    """Gateway connection protocol.
    """

    ik_ev2 = "IKEv2"
    ik_ev1 = "IKEv1"

class VirtualNetworkGatewayConnectionStatus(str, Enum):
    """Virtual Network Gateway connection status.
    """

    unknown = "Unknown"
    connecting = "Connecting"
    connected = "Connected"
    not_connected = "NotConnected"

class VirtualNetworkGatewayConnectionType(str, Enum):
    """Gateway connection type.
    """

    i_psec = "IPsec"
    vnet2_vnet = "Vnet2Vnet"
    express_route = "ExpressRoute"
    vpn_client = "VPNClient"

class VirtualNetworkGatewaySkuName(str, Enum):
    """Gateway SKU name.
    """

    basic = "Basic"
    high_performance = "HighPerformance"
    standard = "Standard"
    ultra_performance = "UltraPerformance"
    vpn_gw1 = "VpnGw1"
    vpn_gw2 = "VpnGw2"
    vpn_gw3 = "VpnGw3"
    vpn_gw4 = "VpnGw4"
    vpn_gw5 = "VpnGw5"
    vpn_gw1_az = "VpnGw1AZ"
    vpn_gw2_az = "VpnGw2AZ"
    vpn_gw3_az = "VpnGw3AZ"
    vpn_gw4_az = "VpnGw4AZ"
    vpn_gw5_az = "VpnGw5AZ"
    er_gw1_az = "ErGw1AZ"
    er_gw2_az = "ErGw2AZ"
    er_gw3_az = "ErGw3AZ"

class VirtualNetworkGatewaySkuTier(str, Enum):
    """Gateway SKU tier.
    """

    basic = "Basic"
    high_performance = "HighPerformance"
    standard = "Standard"
    ultra_performance = "UltraPerformance"
    vpn_gw1 = "VpnGw1"
    vpn_gw2 = "VpnGw2"
    vpn_gw3 = "VpnGw3"
    vpn_gw4 = "VpnGw4"
    vpn_gw5 = "VpnGw5"
    vpn_gw1_az = "VpnGw1AZ"
    vpn_gw2_az = "VpnGw2AZ"
    vpn_gw3_az = "VpnGw3AZ"
    vpn_gw4_az = "VpnGw4AZ"
    vpn_gw5_az = "VpnGw5AZ"
    er_gw1_az = "ErGw1AZ"
    er_gw2_az = "ErGw2AZ"
    er_gw3_az = "ErGw3AZ"

class VirtualNetworkGatewayType(str, Enum):
    """The type of this virtual network gateway.
    """

    vpn = "Vpn"
    express_route = "ExpressRoute"

class VirtualNetworkPeeringState(str, Enum):
    """The status of the virtual network peering.
    """

    initiated = "Initiated"
    connected = "Connected"
    disconnected = "Disconnected"

class VirtualWanSecurityProviderType(str, Enum):
    """The virtual wan security provider type.
    """

    external = "External"
    native = "Native"

class VpnClientProtocol(str, Enum):
    """VPN client protocol enabled for the virtual network gateway.
    """

    ike_v2 = "IkeV2"
    sstp = "SSTP"
    open_vpn = "OpenVPN"

class VpnConnectionStatus(str, Enum):
    """The current state of the vpn connection.
    """

    unknown = "Unknown"
    connecting = "Connecting"
    connected = "Connected"
    not_connected = "NotConnected"

class VpnGatewayGeneration(str, Enum):
    """The generation for this VirtualNetworkGateway. Must be None if gatewayType is not VPN.
    """

    none = "None"
    generation1 = "Generation1"
    generation2 = "Generation2"

class VpnGatewayTunnelingProtocol(str, Enum):
    """VPN protocol enabled for the P2SVpnServerConfiguration.
    """

    ike_v2 = "IkeV2"
    open_vpn = "OpenVPN"

class VpnType(str, Enum):
    """The type of this virtual network gateway.
    """

    policy_based = "PolicyBased"
    route_based = "RouteBased"

class WebApplicationFirewallAction(str, Enum):
    """Type of Actions.
    """

    allow = "Allow"
    block = "Block"
    log = "Log"

class WebApplicationFirewallEnabledState(str, Enum):
    """Describes if the policy is in enabled state or disabled state.
    """

    disabled = "Disabled"
    enabled = "Enabled"

class WebApplicationFirewallMatchVariable(str, Enum):
    """Match Variable.
    """

    remote_addr = "RemoteAddr"
    request_method = "RequestMethod"
    query_string = "QueryString"
    post_args = "PostArgs"
    request_uri = "RequestUri"
    request_headers = "RequestHeaders"
    request_body = "RequestBody"
    request_cookies = "RequestCookies"

class WebApplicationFirewallMode(str, Enum):
    """Describes if it is in detection mode or prevention mode at policy level.
    """

    prevention = "Prevention"
    detection = "Detection"

class WebApplicationFirewallOperator(str, Enum):
    """Describes operator to be matched.
    """

    ip_match = "IPMatch"
    equal = "Equal"
    contains = "Contains"
    less_than = "LessThan"
    greater_than = "GreaterThan"
    less_than_or_equal = "LessThanOrEqual"
    greater_than_or_equal = "GreaterThanOrEqual"
    begins_with = "BeginsWith"
    ends_with = "EndsWith"
    regex = "Regex"

class WebApplicationFirewallPolicyResourceState(str, Enum):
    """Resource status of the policy.
    """

    creating = "Creating"
    enabling = "Enabling"
    enabled = "Enabled"
    disabling = "Disabling"
    disabled = "Disabled"
    deleting = "Deleting"

class WebApplicationFirewallRuleType(str, Enum):
    """Describes type of rule.
    """

    match_rule = "MatchRule"
    invalid = "Invalid"

class WebApplicationFirewallTransform(str, Enum):
    """Describes what transforms applied before matching.
    """

    lowercase = "Lowercase"
    trim = "Trim"
    url_decode = "UrlDecode"
    url_encode = "UrlEncode"
    remove_nulls = "RemoveNulls"
    html_entity_decode = "HtmlEntityDecode"
