# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class Access(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates whether the traffic is allowed or denied.
    """

    ALLOW = "Allow"
    DENY = "Deny"

class ApplicationGatewayBackendHealthServerHealth(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Health of backend server.
    """

    UNKNOWN = "Unknown"
    UP = "Up"
    DOWN = "Down"
    PARTIAL = "Partial"
    DRAINING = "Draining"

class ApplicationGatewayCookieBasedAffinity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Cookie based affinity.
    """

    ENABLED = "Enabled"
    DISABLED = "Disabled"

class ApplicationGatewayFirewallMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Web application firewall mode.
    """

    DETECTION = "Detection"
    PREVENTION = "Prevention"

class ApplicationGatewayOperationalState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Operational state of the application gateway resource.
    """

    STOPPED = "Stopped"
    STARTING = "Starting"
    RUNNING = "Running"
    STOPPING = "Stopping"

class ApplicationGatewayProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Protocol.
    """

    HTTP = "Http"
    HTTPS = "Https"

class ApplicationGatewayRequestRoutingRuleType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Rule type.
    """

    BASIC = "Basic"
    PATH_BASED_ROUTING = "PathBasedRouting"

class ApplicationGatewaySkuName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Name of an application gateway SKU.
    """

    STANDARD_SMALL = "Standard_Small"
    STANDARD_MEDIUM = "Standard_Medium"
    STANDARD_LARGE = "Standard_Large"
    WAF_MEDIUM = "WAF_Medium"
    WAF_LARGE = "WAF_Large"

class ApplicationGatewaySslProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    TL_SV1_0 = "TLSv1_0"
    TL_SV1_1 = "TLSv1_1"
    TL_SV1_2 = "TLSv1_2"

class ApplicationGatewayTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Tier of an application gateway.
    """

    STANDARD = "Standard"
    WAF = "WAF"

class AssociationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The association type of the child resource to the parent resource.
    """

    ASSOCIATED = "Associated"
    CONTAINS = "Contains"

class AuthorizationUseStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """AuthorizationUseStatus. Possible values are: 'Available' and 'InUse'.
    """

    AVAILABLE = "Available"
    IN_USE = "InUse"

class BgpPeerState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The BGP peer state
    """

    UNKNOWN = "Unknown"
    STOPPED = "Stopped"
    IDLE = "Idle"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"

class ConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The connection status.
    """

    UNKNOWN = "Unknown"
    CONNECTED = "Connected"
    DISCONNECTED = "Disconnected"
    DEGRADED = "Degraded"

class DhGroup(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The DH Groups used in IKE Phase 1 for initial SA.
    """

    NONE = "None"
    DH_GROUP1 = "DHGroup1"
    DH_GROUP2 = "DHGroup2"
    DH_GROUP14 = "DHGroup14"
    DH_GROUP2048 = "DHGroup2048"
    ECP256 = "ECP256"
    ECP384 = "ECP384"
    DH_GROUP24 = "DHGroup24"

class Direction(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The direction of the packet represented as a 5-tuple.
    """

    INBOUND = "Inbound"
    OUTBOUND = "Outbound"

class EffectiveRouteSource(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Who created the route. Possible values are: 'Unknown', 'User', 'VirtualNetworkGateway', and
    'Default'.
    """

    UNKNOWN = "Unknown"
    USER = "User"
    VIRTUAL_NETWORK_GATEWAY = "VirtualNetworkGateway"
    DEFAULT = "Default"

class EffectiveRouteState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The value of effective route. Possible values are: 'Active' and 'Invalid'.
    """

    ACTIVE = "Active"
    INVALID = "Invalid"

class ExpressRouteCircuitPeeringAdvertisedPublicPrefixState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """AdvertisedPublicPrefixState of the Peering resource. Possible values are 'NotConfigured',
    'Configuring', 'Configured', and 'ValidationNeeded'.
    """

    NOT_CONFIGURED = "NotConfigured"
    CONFIGURING = "Configuring"
    CONFIGURED = "Configured"
    VALIDATION_NEEDED = "ValidationNeeded"

class ExpressRouteCircuitPeeringState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The state of peering. Possible values are: 'Disabled' and 'Enabled'
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class ExpressRouteCircuitPeeringType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The PeeringType. Possible values are: 'AzurePublicPeering', 'AzurePrivatePeering', and
    'MicrosoftPeering'.
    """

    AZURE_PUBLIC_PEERING = "AzurePublicPeering"
    AZURE_PRIVATE_PEERING = "AzurePrivatePeering"
    MICROSOFT_PEERING = "MicrosoftPeering"

class ExpressRouteCircuitSkuFamily(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The family of the SKU. Possible values are: 'UnlimitedData' and 'MeteredData'.
    """

    UNLIMITED_DATA = "UnlimitedData"
    METERED_DATA = "MeteredData"

class ExpressRouteCircuitSkuTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The tier of the SKU. Possible values are 'Standard' and 'Premium'.
    """

    STANDARD = "Standard"
    PREMIUM = "Premium"

class IkeEncryption(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The IKE encryption algorithm (IKE phase 2).
    """

    DES = "DES"
    DES3 = "DES3"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"

class IkeIntegrity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The IKE integrity algorithm (IKE phase 2).
    """

    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA384 = "SHA384"

class IPAllocationMethod(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """PrivateIP allocation method.
    """

    STATIC = "Static"
    DYNAMIC = "Dynamic"

class IpsecEncryption(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The IPSec encryption algorithm (IKE phase 1).
    """

    NONE = "None"
    DES = "DES"
    DES3 = "DES3"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"
    GCMAES128 = "GCMAES128"
    GCMAES192 = "GCMAES192"
    GCMAES256 = "GCMAES256"

class IpsecIntegrity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The IPSec integrity algorithm (IKE phase 1).
    """

    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    GCMAES128 = "GCMAES128"
    GCMAES192 = "GCMAES192"
    GCMAES256 = "GCMAES256"

class IPVersion(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Available from Api-Version 2016-03-30 onwards, it represents whether the specific
    ipconfiguration is IPv4 or IPv6. Default is taken as IPv4.  Possible values are: 'IPv4' and
    'IPv6'.
    """

    I_PV4 = "IPv4"
    I_PV6 = "IPv6"

class IssueType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of issue.
    """

    UNKNOWN = "Unknown"
    AGENT_STOPPED = "AgentStopped"
    GUEST_FIREWALL = "GuestFirewall"
    DNS_RESOLUTION = "DnsResolution"
    SOCKET_BIND = "SocketBind"
    NETWORK_SECURITY_RULE = "NetworkSecurityRule"
    USER_DEFINED_ROUTE = "UserDefinedRoute"
    PORT_THROTTLED = "PortThrottled"
    PLATFORM = "Platform"

class LoadDistribution(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The load distribution policy for this rule. Possible values are 'Default', 'SourceIP', and
    'SourceIPProtocol'.
    """

    DEFAULT = "Default"
    SOURCE_IP = "SourceIP"
    SOURCE_IP_PROTOCOL = "SourceIPProtocol"

class NetworkOperationStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Status of the Azure async operation. Possible values are: 'InProgress', 'Succeeded', and
    'Failed'.
    """

    IN_PROGRESS = "InProgress"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"

class NextHopType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Next hop type.
    """

    INTERNET = "Internet"
    VIRTUAL_APPLIANCE = "VirtualAppliance"
    VIRTUAL_NETWORK_GATEWAY = "VirtualNetworkGateway"
    VNET_LOCAL = "VnetLocal"
    HYPER_NET_GATEWAY = "HyperNetGateway"
    NONE = "None"

class Origin(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The origin of the issue.
    """

    LOCAL = "Local"
    INBOUND = "Inbound"
    OUTBOUND = "Outbound"

class PcError(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    INTERNAL_ERROR = "InternalError"
    AGENT_STOPPED = "AgentStopped"
    CAPTURE_FAILED = "CaptureFailed"
    LOCAL_FILE_FAILED = "LocalFileFailed"
    STORAGE_FAILED = "StorageFailed"

class PcProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Protocol to be filtered on.
    """

    TCP = "TCP"
    UDP = "UDP"
    ANY = "Any"

class PcStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the packet capture session.
    """

    NOT_STARTED = "NotStarted"
    RUNNING = "Running"
    STOPPED = "Stopped"
    ERROR = "Error"
    UNKNOWN = "Unknown"

class PfsGroup(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The DH Groups used in IKE Phase 2 for new child SA.
    """

    NONE = "None"
    PFS1 = "PFS1"
    PFS2 = "PFS2"
    PFS2048 = "PFS2048"
    ECP256 = "ECP256"
    ECP384 = "ECP384"
    PFS24 = "PFS24"

class ProbeProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The protocol of the end point. Possible values are: 'Http' or 'Tcp'. If 'Tcp' is specified, a
    received ACK is required for the probe to be successful. If 'Http' is specified, a 200 OK
    response from the specifies URI is required for the probe to be successful.
    """

    HTTP = "Http"
    TCP = "Tcp"

class ProcessorArchitecture(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """VPN client Processor Architecture. Possible values are: 'AMD64' and 'X86'.
    """

    AMD64 = "Amd64"
    X86 = "X86"

class Protocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Protocol to be verified on.
    """

    TCP = "TCP"
    UDP = "UDP"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provisioning state of the resource.
    """

    SUCCEEDED = "Succeeded"
    UPDATING = "Updating"
    DELETING = "Deleting"
    FAILED = "Failed"

class RouteFilterRuleType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The rule type of the rule. Valid value is: 'Community'
    """

    COMMUNITY = "Community"

class RouteNextHopType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of Azure hop the packet should be sent to. Possible values are:
    'VirtualNetworkGateway', 'VnetLocal', 'Internet', 'VirtualAppliance', and 'None'.
    """

    VIRTUAL_NETWORK_GATEWAY = "VirtualNetworkGateway"
    VNET_LOCAL = "VnetLocal"
    INTERNET = "Internet"
    VIRTUAL_APPLIANCE = "VirtualAppliance"
    NONE = "None"

class SecurityRuleAccess(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Whether network traffic is allowed or denied. Possible values are: 'Allow' and 'Deny'.
    """

    ALLOW = "Allow"
    DENY = "Deny"

class SecurityRuleDirection(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The direction of the rule. Possible values are: 'Inbound and Outbound'.
    """

    INBOUND = "Inbound"
    OUTBOUND = "Outbound"

class SecurityRuleProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The network protocol this rule applies to. Possible values are: 'Tcp', 'Udp', and '*'.
    """

    TCP = "Tcp"
    UDP = "Udp"
    ASTERISK = "*"

class ServiceProviderProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The ServiceProviderProvisioningState state of the resource. Possible values are
    'NotProvisioned', 'Provisioning', 'Provisioned', and 'Deprovisioning'.
    """

    NOT_PROVISIONED = "NotProvisioned"
    PROVISIONING = "Provisioning"
    PROVISIONED = "Provisioned"
    DEPROVISIONING = "Deprovisioning"

class Severity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The severity of the issue.
    """

    ERROR = "Error"
    WARNING = "Warning"

class TransportProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The transport protocol for the external endpoint. Possible values are 'Udp' or 'Tcp'
    """

    UDP = "Udp"
    TCP = "Tcp"

class UsageUnit(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """An enum describing the unit of measurement.
    """

    COUNT = "Count"

class VirtualNetworkGatewayConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Virtual network Gateway connection status
    """

    UNKNOWN = "Unknown"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    NOT_CONNECTED = "NotConnected"

class VirtualNetworkGatewayConnectionType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gateway connection type. Possible values are: 'IPsec','Vnet2Vnet','ExpressRoute', and
    'VPNClient.
    """

    I_PSEC = "IPsec"
    VNET2_VNET = "Vnet2Vnet"
    EXPRESS_ROUTE = "ExpressRoute"
    VPN_CLIENT = "VPNClient"

class VirtualNetworkGatewaySkuName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gateway SKU name.
    """

    BASIC = "Basic"
    HIGH_PERFORMANCE = "HighPerformance"
    STANDARD = "Standard"
    ULTRA_PERFORMANCE = "UltraPerformance"
    VPN_GW1 = "VpnGw1"
    VPN_GW2 = "VpnGw2"
    VPN_GW3 = "VpnGw3"

class VirtualNetworkGatewaySkuTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gateway SKU tier.
    """

    BASIC = "Basic"
    HIGH_PERFORMANCE = "HighPerformance"
    STANDARD = "Standard"
    ULTRA_PERFORMANCE = "UltraPerformance"
    VPN_GW1 = "VpnGw1"
    VPN_GW2 = "VpnGw2"
    VPN_GW3 = "VpnGw3"

class VirtualNetworkGatewayType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of this virtual network gateway. Possible values are: 'Vpn' and 'ExpressRoute'.
    """

    VPN = "Vpn"
    EXPRESS_ROUTE = "ExpressRoute"

class VirtualNetworkPeeringState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The status of the virtual network peering. Possible values are 'Initiated', 'Connected', and
    'Disconnected'.
    """

    INITIATED = "Initiated"
    CONNECTED = "Connected"
    DISCONNECTED = "Disconnected"

class VpnType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of this virtual network gateway. Possible values are: 'PolicyBased' and 'RouteBased'.
    """

    POLICY_BASED = "PolicyBased"
    ROUTE_BASED = "RouteBased"
