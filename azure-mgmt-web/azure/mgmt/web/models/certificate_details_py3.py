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


class CertificateDetails(Model):
    """SSL certificate details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar version: Certificate Version.
    :vartype version: int
    :ivar serial_number: Certificate Serial Number.
    :vartype serial_number: str
    :ivar thumbprint: Certificate Thumbprint.
    :vartype thumbprint: str
    :ivar subject: Certificate Subject.
    :vartype subject: str
    :ivar not_before: Date Certificate is valid from.
    :vartype not_before: datetime
    :ivar not_after: Date Certificate is valid to.
    :vartype not_after: datetime
    :ivar signature_algorithm: Certificate Signature algorithm.
    :vartype signature_algorithm: str
    :ivar issuer: Certificate Issuer.
    :vartype issuer: str
    :ivar raw_data: Raw certificate data.
    :vartype raw_data: str
    """

    _validation = {
        'version': {'readonly': True},
        'serial_number': {'readonly': True},
        'thumbprint': {'readonly': True},
        'subject': {'readonly': True},
        'not_before': {'readonly': True},
        'not_after': {'readonly': True},
        'signature_algorithm': {'readonly': True},
        'issuer': {'readonly': True},
        'raw_data': {'readonly': True},
    }

    _attribute_map = {
        'version': {'key': 'version', 'type': 'int'},
        'serial_number': {'key': 'serialNumber', 'type': 'str'},
        'thumbprint': {'key': 'thumbprint', 'type': 'str'},
        'subject': {'key': 'subject', 'type': 'str'},
        'not_before': {'key': 'notBefore', 'type': 'iso-8601'},
        'not_after': {'key': 'notAfter', 'type': 'iso-8601'},
        'signature_algorithm': {'key': 'signatureAlgorithm', 'type': 'str'},
        'issuer': {'key': 'issuer', 'type': 'str'},
        'raw_data': {'key': 'rawData', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(CertificateDetails, self).__init__(**kwargs)
        self.version = None
        self.serial_number = None
        self.thumbprint = None
        self.subject = None
        self.not_before = None
        self.not_after = None
        self.signature_algorithm = None
        self.issuer = None
        self.raw_data = None
