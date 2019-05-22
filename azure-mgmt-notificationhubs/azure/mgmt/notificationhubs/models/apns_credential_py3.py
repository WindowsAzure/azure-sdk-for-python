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


class ApnsCredential(Model):
    """Description of a NotificationHub ApnsCredential.

    :param apns_certificate: The APNS certificate.
    :type apns_certificate: str
    :param certificate_key: The certificate key.
    :type certificate_key: str
    :param endpoint: The endpoint of this credential.
    :type endpoint: str
    :param thumbprint: The APNS certificate Thumbprint
    :type thumbprint: str
    :param key_id: A 10-character key identifier (kid) key, obtained from your
     developer account
    :type key_id: str
    :param app_name: The name of the application
    :type app_name: str
    :param app_id: The issuer (iss) registered claim key, whose value is your
     10-character Team ID, obtained from your developer account
    :type app_id: str
    :param token: Provider Authentication Token, obtained through your
     developer account
    :type token: str
    """

    _attribute_map = {
        'apns_certificate': {'key': 'properties.apnsCertificate', 'type': 'str'},
        'certificate_key': {'key': 'properties.certificateKey', 'type': 'str'},
        'endpoint': {'key': 'properties.endpoint', 'type': 'str'},
        'thumbprint': {'key': 'properties.thumbprint', 'type': 'str'},
        'key_id': {'key': 'properties.keyId', 'type': 'str'},
        'app_name': {'key': 'properties.appName', 'type': 'str'},
        'app_id': {'key': 'properties.appId', 'type': 'str'},
        'token': {'key': 'properties.token', 'type': 'str'},
    }

    def __init__(self, *, apns_certificate: str=None, certificate_key: str=None, endpoint: str=None, thumbprint: str=None, key_id: str=None, app_name: str=None, app_id: str=None, token: str=None, **kwargs) -> None:
        super(ApnsCredential, self).__init__(**kwargs)
        self.apns_certificate = apns_certificate
        self.certificate_key = certificate_key
        self.endpoint = endpoint
        self.thumbprint = thumbprint
        self.key_id = key_id
        self.app_name = app_name
        self.app_id = app_id
        self.token = token
