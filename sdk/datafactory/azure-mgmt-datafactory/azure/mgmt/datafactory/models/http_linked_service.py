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

from .linked_service import LinkedService


class HttpLinkedService(LinkedService):
    """Linked service for an HTTP source.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param connect_via: The integration runtime reference.
    :type connect_via:
     ~azure.mgmt.datafactory.models.IntegrationRuntimeReference
    :param description: Linked service description.
    :type description: str
    :param parameters: Parameters for linked service.
    :type parameters: dict[str,
     ~azure.mgmt.datafactory.models.ParameterSpecification]
    :param annotations: List of tags that can be used for describing the
     linked service.
    :type annotations: list[object]
    :param type: Required. Constant filled by server.
    :type type: str
    :param url: Required. The base URL of the HTTP endpoint, e.g.
     http://www.microsoft.com. Type: string (or Expression with resultType
     string).
    :type url: object
    :param authentication_type: The authentication type to be used to connect
     to the HTTP server. Possible values include: 'Basic', 'Anonymous',
     'Digest', 'Windows', 'ClientCertificate'
    :type authentication_type: str or
     ~azure.mgmt.datafactory.models.HttpAuthenticationType
    :param user_name: User name for Basic, Digest, or Windows authentication.
     Type: string (or Expression with resultType string).
    :type user_name: object
    :param password: Password for Basic, Digest, Windows, or ClientCertificate
     with EmbeddedCertData authentication.
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    :param embedded_cert_data: Base64 encoded certificate data for
     ClientCertificate authentication. For on-premises copy with
     ClientCertificate authentication, either CertThumbprint or
     EmbeddedCertData/Password should be specified. Type: string (or Expression
     with resultType string).
    :type embedded_cert_data: object
    :param cert_thumbprint: Thumbprint of certificate for ClientCertificate
     authentication. Only valid for on-premises copy. For on-premises copy with
     ClientCertificate authentication, either CertThumbprint or
     EmbeddedCertData/Password should be specified. Type: string (or Expression
     with resultType string).
    :type cert_thumbprint: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    :param enable_server_certificate_validation: If true, validate the HTTPS
     server SSL certificate. Default value is true. Type: boolean (or
     Expression with resultType boolean).
    :type enable_server_certificate_validation: object
    """

    _validation = {
        'type': {'required': True},
        'url': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'url': {'key': 'typeProperties.url', 'type': 'object'},
        'authentication_type': {'key': 'typeProperties.authenticationType', 'type': 'str'},
        'user_name': {'key': 'typeProperties.userName', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecretBase'},
        'embedded_cert_data': {'key': 'typeProperties.embeddedCertData', 'type': 'object'},
        'cert_thumbprint': {'key': 'typeProperties.certThumbprint', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
        'enable_server_certificate_validation': {'key': 'typeProperties.enableServerCertificateValidation', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(HttpLinkedService, self).__init__(**kwargs)
        self.url = kwargs.get('url', None)
        self.authentication_type = kwargs.get('authentication_type', None)
        self.user_name = kwargs.get('user_name', None)
        self.password = kwargs.get('password', None)
        self.embedded_cert_data = kwargs.get('embedded_cert_data', None)
        self.cert_thumbprint = kwargs.get('cert_thumbprint', None)
        self.encrypted_credential = kwargs.get('encrypted_credential', None)
        self.enable_server_certificate_validation = kwargs.get('enable_server_certificate_validation', None)
        self.type = 'HttpServer'
