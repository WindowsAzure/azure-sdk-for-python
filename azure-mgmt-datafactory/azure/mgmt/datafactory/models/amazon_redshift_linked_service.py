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


class AmazonRedshiftLinkedService(LinkedService):
    """Linked service for Amazon Redshift.

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
    :param server: Required. The name of the Amazon Redshift server. Type:
     string (or Expression with resultType string).
    :type server: object
    :param username: The username of the Amazon Redshift source. Type: string
     (or Expression with resultType string).
    :type username: object
    :param password: The password of the Amazon Redshift source.
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    :param database: Required. The database name of the Amazon Redshift
     source. Type: string (or Expression with resultType string).
    :type database: object
    :param port: The TCP port number that the Amazon Redshift server uses to
     listen for client connections. The default value is 5439. Type: integer
     (or Expression with resultType integer).
    :type port: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'server': {'required': True},
        'database': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'server': {'key': 'typeProperties.server', 'type': 'object'},
        'username': {'key': 'typeProperties.username', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecretBase'},
        'database': {'key': 'typeProperties.database', 'type': 'object'},
        'port': {'key': 'typeProperties.port', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(AmazonRedshiftLinkedService, self).__init__(**kwargs)
        self.server = kwargs.get('server', None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        self.database = kwargs.get('database', None)
        self.port = kwargs.get('port', None)
        self.encrypted_credential = kwargs.get('encrypted_credential', None)
        self.type = 'AmazonRedshift'
