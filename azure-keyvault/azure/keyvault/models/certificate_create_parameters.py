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


class CertificateCreateParameters(Model):
    """The certificate create parameters.

    :param certificate_policy: The management policy for the certificate.
    :type certificate_policy: :class:`CertificatePolicy
     <azure.keyvault.models.CertificatePolicy>`
    :param certificate_attributes: The attributes of the certificate
     (optional).
    :type certificate_attributes: :class:`CertificateAttributes
     <azure.keyvault.models.CertificateAttributes>`
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict
    """

    _attribute_map = {
        'certificate_policy': {'key': 'policy', 'type': 'CertificatePolicy'},
        'certificate_attributes': {'key': 'attributes', 'type': 'CertificateAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, certificate_policy=None, certificate_attributes=None, tags=None):
        self.certificate_policy = certificate_policy
        self.certificate_attributes = certificate_attributes
        self.tags = tags
