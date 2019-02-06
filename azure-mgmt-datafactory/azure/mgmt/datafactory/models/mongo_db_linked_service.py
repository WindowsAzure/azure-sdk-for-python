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


class MongoDbLinkedService(LinkedService):
    """Linked service for MongoDb data source.

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
    :param server: Required. The IP address or server name of the MongoDB
     server. Type: string (or Expression with resultType string).
    :type server: object
    :param authentication_type: The authentication type to be used to connect
     to the MongoDB database. Possible values include: 'Basic', 'Anonymous'
    :type authentication_type: str or
     ~azure.mgmt.datafactory.models.MongoDbAuthenticationType
    :param database_name: Required. The name of the MongoDB database that you
     want to access. Type: string (or Expression with resultType string).
    :type database_name: object
    :param username: Username for authentication. Type: string (or Expression
     with resultType string).
    :type username: object
    :param password: Password for authentication.
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    :param auth_source: Database to verify the username and password. Type:
     string (or Expression with resultType string).
    :type auth_source: object
    :param port: The TCP port number that the MongoDB server uses to listen
     for client connections. The default value is 27017. Type: integer (or
     Expression with resultType integer), minimum: 0.
    :type port: object
    :param enable_ssl: Specifies whether the connections to the server are
     encrypted using SSL. The default value is false. Type: boolean (or
     Expression with resultType boolean).
    :type enable_ssl: object
    :param allow_self_signed_server_cert: Specifies whether to allow
     self-signed certificates from the server. The default value is false.
     Type: boolean (or Expression with resultType boolean).
    :type allow_self_signed_server_cert: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'server': {'required': True},
        'database_name': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'server': {'key': 'typeProperties.server', 'type': 'object'},
        'authentication_type': {'key': 'typeProperties.authenticationType', 'type': 'str'},
        'database_name': {'key': 'typeProperties.databaseName', 'type': 'object'},
        'username': {'key': 'typeProperties.username', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecretBase'},
        'auth_source': {'key': 'typeProperties.authSource', 'type': 'object'},
        'port': {'key': 'typeProperties.port', 'type': 'object'},
        'enable_ssl': {'key': 'typeProperties.enableSsl', 'type': 'object'},
        'allow_self_signed_server_cert': {'key': 'typeProperties.allowSelfSignedServerCert', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(MongoDbLinkedService, self).__init__(**kwargs)
        self.server = kwargs.get('server', None)
        self.authentication_type = kwargs.get('authentication_type', None)
        self.database_name = kwargs.get('database_name', None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        self.auth_source = kwargs.get('auth_source', None)
        self.port = kwargs.get('port', None)
        self.enable_ssl = kwargs.get('enable_ssl', None)
        self.allow_self_signed_server_cert = kwargs.get('allow_self_signed_server_cert', None)
        self.encrypted_credential = kwargs.get('encrypted_credential', None)
        self.type = 'MongoDb'
