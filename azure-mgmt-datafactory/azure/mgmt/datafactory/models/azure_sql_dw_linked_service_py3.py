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


class AzureSqlDWLinkedService(LinkedService):
    """Azure SQL Data Warehouse linked service.

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
    :param connection_string: Required. The connection string. Type: string,
     SecureString or AzureKeyVaultSecretReference. Type: string, SecureString
     or AzureKeyVaultSecretReference.
    :type connection_string: object
    :param password: The Azure key vault secret reference of password in
     connection string.
    :type password:
     ~azure.mgmt.datafactory.models.AzureKeyVaultSecretReference
    :param service_principal_id: The ID of the service principal used to
     authenticate against Azure SQL Data Warehouse. Type: string (or Expression
     with resultType string).
    :type service_principal_id: object
    :param service_principal_key: The key of the service principal used to
     authenticate against Azure SQL Data Warehouse.
    :type service_principal_key: ~azure.mgmt.datafactory.models.SecretBase
    :param tenant: The name or ID of the tenant to which the service principal
     belongs. Type: string (or Expression with resultType string).
    :type tenant: object
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
        'password': {'key': 'typeProperties.password', 'type': 'AzureKeyVaultSecretReference'},
        'service_principal_id': {'key': 'typeProperties.servicePrincipalId', 'type': 'object'},
        'service_principal_key': {'key': 'typeProperties.servicePrincipalKey', 'type': 'SecretBase'},
        'tenant': {'key': 'typeProperties.tenant', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, *, connection_string, additional_properties=None, connect_via=None, description: str=None, parameters=None, annotations=None, password=None, service_principal_id=None, service_principal_key=None, tenant=None, encrypted_credential=None, **kwargs) -> None:
        super(AzureSqlDWLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations, **kwargs)
        self.connection_string = connection_string
        self.password = password
        self.service_principal_id = service_principal_id
        self.service_principal_key = service_principal_key
        self.tenant = tenant
        self.encrypted_credential = encrypted_credential
        self.type = 'AzureSqlDW'
