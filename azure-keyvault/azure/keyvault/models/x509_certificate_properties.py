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


class X509CertificateProperties(Model):
    """Properties of the X509 component of a certificate.

    :param subject: The subject name. Should be a valid X509 distinguished
     Name.
    :type subject: str
    :param ekus: The enhanced key usage.
    :type ekus: list[str]
    :param subject_alternative_names: The subject alternative names.
    :type subject_alternative_names:
     ~azure.keyvault.models.SubjectAlternativeNames
    :param key_usage: List of key usages.
    :type key_usage: list[str or ~azure.keyvault.models.KeyUsageType]
    :param validity_in_months: The duration that the ceritifcate is valid in
     months.
    :type validity_in_months: int
    :param certificate_transparency: Indicates if the certificates generated
     under this policy should be published to certificate transparency logs.
    :type certificate_transparency: bool
    """

    _validation = {
        'validity_in_months': {'minimum': 0},
    }

    _attribute_map = {
        'subject': {'key': 'subject', 'type': 'str'},
        'ekus': {'key': 'ekus', 'type': '[str]'},
        'subject_alternative_names': {'key': 'sans', 'type': 'SubjectAlternativeNames'},
        'key_usage': {'key': 'key_usage', 'type': '[str]'},
        'validity_in_months': {'key': 'validity_months', 'type': 'int'},
        'certificate_transparency': {'key': 'cert_transparency', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(X509CertificateProperties, self).__init__(**kwargs)
        self.subject = kwargs.get('subject', None)
        self.ekus = kwargs.get('ekus', None)
        self.subject_alternative_names = kwargs.get('subject_alternative_names', None)
        self.key_usage = kwargs.get('key_usage', None)
        self.validity_in_months = kwargs.get('validity_in_months', None)
        self.certificate_transparency = kwargs.get('certificate_transparency', None)
