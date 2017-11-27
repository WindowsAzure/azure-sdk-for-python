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

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param connect_via: The integration runtime reference.
    :type connect_via:
     ~azure.mgmt.datafactory.models.IntegrationRuntimeReference
    :param description: Linked service description.
    :type description: str
    :param type: Constant filled by server.
    :type type: str
    :param server: The IP address or server name of the MongoDB server. Type:
     string (or Expression with resultType string).
    :type server: object
    :param authentication_type: The authentication type to be used to connect
     to the MongoDB database. Possible values include: 'Basic', 'Anonymous'
    :type authentication_type: str or
     ~azure.mgmt.datafactory.models.MongoDbAuthenticationType
    :param database_name: The name of the MongoDB database that you want to
     access. Type: string (or Expression with resultType string).
    :type database_name: object
    :param username: Username for authentication. Type: string (or Expression
     with resultType string).
    :type username: object
    :param password: Password for authentication.
    :type password: ~azure.mgmt.datafactory.models.SecureString
    :param auth_source: Database to verify the username and password. Type:
     string (or Expression with resultType string).
    :type auth_source: object
    :param port: The TCP port number that the MongoDB server uses to listen
     for client connections. The default value is 27017. Type: integer (or
     Expression with resultType integer), minimum: 0.
    :type port: object
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
        'type': {'key': 'type', 'type': 'str'},
        'server': {'key': 'typeProperties.server', 'type': 'object'},
        'authentication_type': {'key': 'typeProperties.authenticationType', 'type': 'str'},
        'database_name': {'key': 'typeProperties.databaseName', 'type': 'object'},
        'username': {'key': 'typeProperties.username', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecureString'},
        'auth_source': {'key': 'typeProperties.authSource', 'type': 'object'},
        'port': {'key': 'typeProperties.port', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, server, database_name, additional_properties=None, connect_via=None, description=None, authentication_type=None, username=None, password=None, auth_source=None, port=None, encrypted_credential=None):
        super(MongoDbLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description)
        self.server = server
        self.authentication_type = authentication_type
        self.database_name = database_name
        self.username = username
        self.password = password
        self.auth_source = auth_source
        self.port = port
        self.encrypted_credential = encrypted_credential
        self.type = 'MongoDb'
