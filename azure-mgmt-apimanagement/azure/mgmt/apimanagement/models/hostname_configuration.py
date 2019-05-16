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


class HostnameConfiguration(Model):
    """Custom hostname configuration.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Hostname type. Possible values include: 'Proxy',
     'Portal', 'Management', 'Scm', 'DeveloperPortal'
    :type type: str or ~azure.mgmt.apimanagement.models.HostnameType
    :param host_name: Required. Hostname to configure on the Api Management
     service.
    :type host_name: str
    :param key_vault_id: Url to the KeyVault Secret containing the Ssl
     Certificate. If absolute Url containing version is provided, auto-update
     of ssl certificate will not work. This requires Api Management service to
     be configured with MSI. The secret should be of type
     *application/x-pkcs12*
    :type key_vault_id: str
    :param encoded_certificate: Base64 Encoded certificate.
    :type encoded_certificate: str
    :param certificate_password: Certificate Password.
    :type certificate_password: str
    :param default_ssl_binding: Specify true to setup the certificate
     associated with this Hostname as the Default SSL Certificate. If a client
     does not send the SNI header, then this will be the certificate that will
     be challenged. The property is useful if a service has multiple custom
     hostname enabled and it needs to decide on the default ssl certificate.
     The setting only applied to Proxy Hostname Type. Default value: False .
    :type default_ssl_binding: bool
    :param negotiate_client_certificate: Specify true to always negotiate
     client certificate on the hostname. Default Value is false. Default value:
     False .
    :type negotiate_client_certificate: bool
    :param certificate: Certificate information.
    :type certificate: ~azure.mgmt.apimanagement.models.CertificateInformation
    """

    _validation = {
        'type': {'required': True},
        'host_name': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'host_name': {'key': 'hostName', 'type': 'str'},
        'key_vault_id': {'key': 'keyVaultId', 'type': 'str'},
        'encoded_certificate': {'key': 'encodedCertificate', 'type': 'str'},
        'certificate_password': {'key': 'certificatePassword', 'type': 'str'},
        'default_ssl_binding': {'key': 'defaultSslBinding', 'type': 'bool'},
        'negotiate_client_certificate': {'key': 'negotiateClientCertificate', 'type': 'bool'},
        'certificate': {'key': 'certificate', 'type': 'CertificateInformation'},
    }

    def __init__(self, **kwargs):
        super(HostnameConfiguration, self).__init__(**kwargs)
        self.type = kwargs.get('type', None)
        self.host_name = kwargs.get('host_name', None)
        self.key_vault_id = kwargs.get('key_vault_id', None)
        self.encoded_certificate = kwargs.get('encoded_certificate', None)
        self.certificate_password = kwargs.get('certificate_password', None)
        self.default_ssl_binding = kwargs.get('default_ssl_binding', False)
        self.negotiate_client_certificate = kwargs.get('negotiate_client_certificate', False)
        self.certificate = kwargs.get('certificate', None)
