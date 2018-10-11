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


class IntegrationRuntimeConnectionInfo(Model):
    """Connection information for encrypting the on-premises data source
    credentials.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :ivar service_token: The token generated in service. Callers use this
     token to authenticate to integration runtime.
    :vartype service_token: str
    :ivar identity_cert_thumbprint: The integration runtime SSL certificate
     thumbprint. Click-Once application uses it to do server validation.
    :vartype identity_cert_thumbprint: str
    :ivar host_service_uri: The on-premises integration runtime host URL.
    :vartype host_service_uri: str
    :ivar version: The integration runtime version.
    :vartype version: str
    :ivar public_key: The public key for encrypting a credential when
     transferring the credential to the integration runtime.
    :vartype public_key: str
    :ivar is_identity_cert_exprired: Whether the identity certificate is
     expired.
    :vartype is_identity_cert_exprired: bool
    """

    _validation = {
        'service_token': {'readonly': True},
        'identity_cert_thumbprint': {'readonly': True},
        'host_service_uri': {'readonly': True},
        'version': {'readonly': True},
        'public_key': {'readonly': True},
        'is_identity_cert_exprired': {'readonly': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'service_token': {'key': 'serviceToken', 'type': 'str'},
        'identity_cert_thumbprint': {'key': 'identityCertThumbprint', 'type': 'str'},
        'host_service_uri': {'key': 'hostServiceUri', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'public_key': {'key': 'publicKey', 'type': 'str'},
        'is_identity_cert_exprired': {'key': 'isIdentityCertExprired', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(IntegrationRuntimeConnectionInfo, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.service_token = None
        self.identity_cert_thumbprint = None
        self.host_service_uri = None
        self.version = None
        self.public_key = None
        self.is_identity_cert_exprired = None
