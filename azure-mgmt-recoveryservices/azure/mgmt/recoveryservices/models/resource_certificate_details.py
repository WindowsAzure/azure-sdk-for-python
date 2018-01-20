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


class ResourceCertificateDetails(Model):
    """Certificate details representing the Vault credentials.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: ResourceCertificateAndAadDetails,
    ResourceCertificateAndAcsDetails

    :param certificate: The base64 encoded certificate raw data string.
    :type certificate: bytearray
    :param friendly_name: Certificate friendlyname.
    :type friendly_name: str
    :param issuer: Certificate issuer.
    :type issuer: str
    :param resource_id: Resource ID of the vault.
    :type resource_id: long
    :param subject: Certificate Subject Name.
    :type subject: str
    :param thumbprint: Certificate thumbprint.
    :type thumbprint: str
    :param valid_from: Certificate Validity start Date time.
    :type valid_from: datetime
    :param valid_to: Certificate Validity End Date time.
    :type valid_to: datetime
    :param auth_type: Constant filled by server.
    :type auth_type: str
    """

    _validation = {
        'auth_type': {'required': True},
    }

    _attribute_map = {
        'certificate': {'key': 'certificate', 'type': 'bytearray'},
        'friendly_name': {'key': 'friendlyName', 'type': 'str'},
        'issuer': {'key': 'issuer', 'type': 'str'},
        'resource_id': {'key': 'resourceId', 'type': 'long'},
        'subject': {'key': 'subject', 'type': 'str'},
        'thumbprint': {'key': 'thumbprint', 'type': 'str'},
        'valid_from': {'key': 'validFrom', 'type': 'iso-8601'},
        'valid_to': {'key': 'validTo', 'type': 'iso-8601'},
        'auth_type': {'key': 'authType', 'type': 'str'},
    }

    _subtype_map = {
        'auth_type': {'AzureActiveDirectory': 'ResourceCertificateAndAadDetails', 'AccessControlService': 'ResourceCertificateAndAcsDetails'}
    }

    def __init__(self, certificate=None, friendly_name=None, issuer=None, resource_id=None, subject=None, thumbprint=None, valid_from=None, valid_to=None):
        super(ResourceCertificateDetails, self).__init__()
        self.certificate = certificate
        self.friendly_name = friendly_name
        self.issuer = issuer
        self.resource_id = resource_id
        self.subject = subject
        self.thumbprint = thumbprint
        self.valid_from = valid_from
        self.valid_to = valid_to
        self.auth_type = None
