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


class CertificateUpdateParameters(Model):
    """The certificate update parameters.

    :param certificate_policy: The management policy for the certificate.
    :type certificate_policy:
     ~azure.keyvault.v2016_10_01.models.CertificatePolicy
    :param certificate_attributes: The attributes of the certificate
     (optional).
    :type certificate_attributes:
     ~azure.keyvault.v2016_10_01.models.CertificateAttributes
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'certificate_policy': {'key': 'policy', 'type': 'CertificatePolicy'},
        'certificate_attributes': {'key': 'attributes', 'type': 'CertificateAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(CertificateUpdateParameters, self).__init__(**kwargs)
        self.certificate_policy = kwargs.get('certificate_policy', None)
        self.certificate_attributes = kwargs.get('certificate_attributes', None)
        self.tags = kwargs.get('tags', None)
