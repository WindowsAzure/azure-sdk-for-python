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

from msrest.serialization import Model


class VpnClientConfiguration(Model):
    """VpnClientConfiguration for P2S client.

    :param vpn_client_address_pool: The reference of the address space
     resource which represents Address space for P2S VpnClient.
    :type vpn_client_address_pool:
     ~azure.mgmt.network.v2017_03_01.models.AddressSpace
    :param vpn_client_root_certificates: VpnClientRootCertificate for virtual
     network gateway.
    :type vpn_client_root_certificates:
     list[~azure.mgmt.network.v2017_03_01.models.VpnClientRootCertificate]
    :param vpn_client_revoked_certificates: VpnClientRevokedCertificate for
     Virtual network gateway.
    :type vpn_client_revoked_certificates:
     list[~azure.mgmt.network.v2017_03_01.models.VpnClientRevokedCertificate]
    """

    _attribute_map = {
        'vpn_client_address_pool': {'key': 'vpnClientAddressPool', 'type': 'AddressSpace'},
        'vpn_client_root_certificates': {'key': 'vpnClientRootCertificates', 'type': '[VpnClientRootCertificate]'},
        'vpn_client_revoked_certificates': {'key': 'vpnClientRevokedCertificates', 'type': '[VpnClientRevokedCertificate]'},
    }

    def __init__(self, vpn_client_address_pool=None, vpn_client_root_certificates=None, vpn_client_revoked_certificates=None):
        super(VpnClientConfiguration, self).__init__()
        self.vpn_client_address_pool = vpn_client_address_pool
        self.vpn_client_root_certificates = vpn_client_root_certificates
        self.vpn_client_revoked_certificates = vpn_client_revoked_certificates
