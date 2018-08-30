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

from .sub_resource import SubResource


class P2SVpnServerConfiguration(SubResource):
    """P2SVpnServerConfiguration Resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param vpn_protocols: vpnProtocols for the P2SVpnServerConfiguration.
    :type vpn_protocols: list[str or
     ~azure.mgmt.network.v2018_08_01.models.VpnGatewayTunnelingProtocol]
    :param p2s_vpn_server_config_vpn_client_root_certificates: VPN client root
     certificate of P2SVpnServerConfiguration.
    :type p2s_vpn_server_config_vpn_client_root_certificates:
     list[~azure.mgmt.network.v2018_08_01.models.P2SVpnServerConfigVpnClientRootCertificate]
    :param p2s_vpn_server_config_vpn_client_revoked_certificates: VPN client
     revoked certificate of P2SVpnServerConfiguration.
    :type p2s_vpn_server_config_vpn_client_revoked_certificates:
     list[~azure.mgmt.network.v2018_08_01.models.P2SVpnServerConfigVpnClientRevokedCertificate]
    :param p2s_vpn_server_config_radius_server_root_certificates: Radius
     Server root certificate of P2SVpnServerConfiguration.
    :type p2s_vpn_server_config_radius_server_root_certificates:
     list[~azure.mgmt.network.v2018_08_01.models.P2SVpnServerConfigRadiusServerRootCertificate]
    :param p2s_vpn_server_config_radius_client_root_certificates: Radius
     client root certificate of P2SVpnServerConfiguration.
    :type p2s_vpn_server_config_radius_client_root_certificates:
     list[~azure.mgmt.network.v2018_08_01.models.P2SVpnServerConfigRadiusClientRootCertificate]
    :param vpn_client_ipsec_policies: VpnClientIpsecPolicies for
     P2SVpnServerConfiguration.
    :type vpn_client_ipsec_policies:
     list[~azure.mgmt.network.v2018_08_01.models.IpsecPolicy]
    :param radius_server_address: The radius server address property of the
     P2SVpnServerConfiguration resource for point to site client connection.
    :type radius_server_address: str
    :param radius_server_secret: The radius secret property of the
     P2SVpnServerConfiguration resource for for point to site client
     connection.
    :type radius_server_secret: str
    :ivar p2s_vpn_gateways:
    :vartype p2s_vpn_gateways:
     list[~azure.mgmt.network.v2018_08_01.models.SubResource]
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :ivar etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :vartype etag: str
    """

    _validation = {
        'p2s_vpn_gateways': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'vpn_protocols': {'key': 'properties.vpnProtocols', 'type': '[str]'},
        'p2s_vpn_server_config_vpn_client_root_certificates': {'key': 'properties.p2sVpnServerConfigVpnClientRootCertificates', 'type': '[P2SVpnServerConfigVpnClientRootCertificate]'},
        'p2s_vpn_server_config_vpn_client_revoked_certificates': {'key': 'properties.p2sVpnServerConfigVpnClientRevokedCertificates', 'type': '[P2SVpnServerConfigVpnClientRevokedCertificate]'},
        'p2s_vpn_server_config_radius_server_root_certificates': {'key': 'properties.p2sVpnServerConfigRadiusServerRootCertificates', 'type': '[P2SVpnServerConfigRadiusServerRootCertificate]'},
        'p2s_vpn_server_config_radius_client_root_certificates': {'key': 'properties.p2sVpnServerConfigRadiusClientRootCertificates', 'type': '[P2SVpnServerConfigRadiusClientRootCertificate]'},
        'vpn_client_ipsec_policies': {'key': 'properties.vpnClientIpsecPolicies', 'type': '[IpsecPolicy]'},
        'radius_server_address': {'key': 'properties.radiusServerAddress', 'type': 'str'},
        'radius_server_secret': {'key': 'properties.radiusServerSecret', 'type': 'str'},
        'p2s_vpn_gateways': {'key': 'properties.p2sVpnGateways', 'type': '[SubResource]'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(P2SVpnServerConfiguration, self).__init__(**kwargs)
        self.vpn_protocols = kwargs.get('vpn_protocols', None)
        self.p2s_vpn_server_config_vpn_client_root_certificates = kwargs.get('p2s_vpn_server_config_vpn_client_root_certificates', None)
        self.p2s_vpn_server_config_vpn_client_revoked_certificates = kwargs.get('p2s_vpn_server_config_vpn_client_revoked_certificates', None)
        self.p2s_vpn_server_config_radius_server_root_certificates = kwargs.get('p2s_vpn_server_config_radius_server_root_certificates', None)
        self.p2s_vpn_server_config_radius_client_root_certificates = kwargs.get('p2s_vpn_server_config_radius_client_root_certificates', None)
        self.vpn_client_ipsec_policies = kwargs.get('vpn_client_ipsec_policies', None)
        self.radius_server_address = kwargs.get('radius_server_address', None)
        self.radius_server_secret = kwargs.get('radius_server_secret', None)
        self.p2s_vpn_gateways = None
        self.name = kwargs.get('name', None)
        self.etag = None
