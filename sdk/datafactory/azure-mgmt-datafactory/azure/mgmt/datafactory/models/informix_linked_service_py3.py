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

from .linked_service_py3 import LinkedService


class InformixLinkedService(LinkedService):
    """Informix linked service.

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
    :param connection_string: Required. The non-access credential portion of
     the connection string as well as an optional encrypted credential. Type:
     string, SecureString or AzureKeyVaultSecretReference.
    :type connection_string: object
    :param authentication_type: Type of authentication used to connect to the
     Informix as ODBC data store. Possible values are: Anonymous and Basic.
     Type: string (or Expression with resultType string).
    :type authentication_type: object
    :param credential: The access credential portion of the connection string
     specified in driver-specific property-value format.
    :type credential: ~azure.mgmt.datafactory.models.SecretBase
    :param user_name: User name for Basic authentication. Type: string (or
     Expression with resultType string).
    :type user_name: object
    :param password: Password for Basic authentication.
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'connection_string': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'connection_string': {'key': 'typeProperties.connectionString', 'type': 'object'},
        'authentication_type': {'key': 'typeProperties.authenticationType', 'type': 'object'},
        'credential': {'key': 'typeProperties.credential', 'type': 'SecretBase'},
        'user_name': {'key': 'typeProperties.userName', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecretBase'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, *, connection_string, additional_properties=None, connect_via=None, description: str=None, parameters=None, annotations=None, authentication_type=None, credential=None, user_name=None, password=None, encrypted_credential=None, **kwargs) -> None:
        super(InformixLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations, **kwargs)
        self.connection_string = connection_string
        self.authentication_type = authentication_type
        self.credential = credential
        self.user_name = user_name
        self.password = password
        self.encrypted_credential = encrypted_credential
        self.type = 'Informix'
