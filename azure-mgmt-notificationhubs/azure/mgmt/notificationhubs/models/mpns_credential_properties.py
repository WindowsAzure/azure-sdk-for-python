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


class MpnsCredentialProperties(Model):
    """Description of a NotificationHub MpnsCredential.

    :param mpns_certificate: Gets or sets the MPNS certificate.
    :type mpns_certificate: str
    :param certificate_key: Gets or sets the certificate key for this
     credential.
    :type certificate_key: str
    :param thumbprint: Gets or sets the Mpns certificate Thumbprint
    :type thumbprint: str
    """ 

    _attribute_map = {
        'mpns_certificate': {'key': 'mpnsCertificate', 'type': 'str'},
        'certificate_key': {'key': 'certificateKey', 'type': 'str'},
        'thumbprint': {'key': 'thumbprint', 'type': 'str'},
    }

    def __init__(self, mpns_certificate=None, certificate_key=None, thumbprint=None):
        self.mpns_certificate = mpns_certificate
        self.certificate_key = certificate_key
        self.thumbprint = thumbprint
