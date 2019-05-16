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

from .custom_domain_https_parameters import CustomDomainHttpsParameters


class CdnManagedHttpsParameters(CustomDomainHttpsParameters):
    """Defines the certificate source parameters using CDN managed certificate for
    enabling SSL.

    All required parameters must be populated in order to send to Azure.

    :param protocol_type: Required. Defines the TLS extension protocol that is
     used for secure delivery. Possible values include: 'ServerNameIndication',
     'IPBased'
    :type protocol_type: str or ~azure.mgmt.cdn.models.ProtocolType
    :param certificate_source: Required. Constant filled by server.
    :type certificate_source: str
    :param certificate_source_parameters: Required. Defines the certificate
     source parameters using CDN managed certificate for enabling SSL.
    :type certificate_source_parameters:
     ~azure.mgmt.cdn.models.CdnCertificateSourceParameters
    """

    _validation = {
        'protocol_type': {'required': True},
        'certificate_source': {'required': True},
        'certificate_source_parameters': {'required': True},
    }

    _attribute_map = {
        'protocol_type': {'key': 'protocolType', 'type': 'str'},
        'certificate_source': {'key': 'certificateSource', 'type': 'str'},
        'certificate_source_parameters': {'key': 'certificateSourceParameters', 'type': 'CdnCertificateSourceParameters'},
    }

    def __init__(self, **kwargs):
        super(CdnManagedHttpsParameters, self).__init__(**kwargs)
        self.certificate_source_parameters = kwargs.get('certificate_source_parameters', None)
        self.certificate_source = 'Cdn'
