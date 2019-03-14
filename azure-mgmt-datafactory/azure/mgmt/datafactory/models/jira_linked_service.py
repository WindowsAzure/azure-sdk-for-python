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


class JiraLinkedService(LinkedService):
    """Jira Service linked service.

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
     Dataset.
    :type annotations: list[object]
    :param type: Required. Constant filled by server.
    :type type: str
    :param host: Required. The IP address or host name of the Jira service.
     (e.g. jira.example.com)
    :type host: object
    :param port: The TCP port that the Jira server uses to listen for client
     connections. The default value is 443 if connecting through HTTPS, or 8080
     if connecting through HTTP.
    :type port: object
    :param username: Required. The user name that you use to access Jira
     Service.
    :type username: object
    :param password: The password corresponding to the user name that you
     provided in the username field.
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    :param use_encrypted_endpoints: Specifies whether the data source
     endpoints are encrypted using HTTPS. The default value is true.
    :type use_encrypted_endpoints: object
    :param use_host_verification: Specifies whether to require the host name
     in the server's certificate to match the host name of the server when
     connecting over SSL. The default value is true.
    :type use_host_verification: object
    :param use_peer_verification: Specifies whether to verify the identity of
     the server when connecting over SSL. The default value is true.
    :type use_peer_verification: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'host': {'required': True},
        'username': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'host': {'key': 'typeProperties.host', 'type': 'object'},
        'port': {'key': 'typeProperties.port', 'type': 'object'},
        'username': {'key': 'typeProperties.username', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecretBase'},
        'use_encrypted_endpoints': {'key': 'typeProperties.useEncryptedEndpoints', 'type': 'object'},
        'use_host_verification': {'key': 'typeProperties.useHostVerification', 'type': 'object'},
        'use_peer_verification': {'key': 'typeProperties.usePeerVerification', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(JiraLinkedService, self).__init__(**kwargs)
        self.host = kwargs.get('host', None)
        self.port = kwargs.get('port', None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        self.use_encrypted_endpoints = kwargs.get('use_encrypted_endpoints', None)
        self.use_host_verification = kwargs.get('use_host_verification', None)
        self.use_peer_verification = kwargs.get('use_peer_verification', None)
        self.encrypted_credential = kwargs.get('encrypted_credential', None)
        self.type = 'Jira'
