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


class CertificateMergeParameters(Model):
    """The certificate merge parameters.

    All required parameters must be populated in order to send to Azure.

    :param x509_certificates: Required. The certificate or the certificate
     chain to merge.
    :type x509_certificates: list[bytearray]
    :param certificate_attributes: The attributes of the certificate
     (optional).
    :type certificate_attributes: ~azure.keyvault.models.CertificateAttributes
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    """

    _validation = {
        'x509_certificates': {'required': True},
    }

    _attribute_map = {
        'x509_certificates': {'key': 'x5c', 'type': '[bytearray]'},
        'certificate_attributes': {'key': 'attributes', 'type': 'CertificateAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(CertificateMergeParameters, self).__init__(**kwargs)
        self.x509_certificates = kwargs.get('x509_certificates', None)
        self.certificate_attributes = kwargs.get('certificate_attributes', None)
        self.tags = kwargs.get('tags', None)
