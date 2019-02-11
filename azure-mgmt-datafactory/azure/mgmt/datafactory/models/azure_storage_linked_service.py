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


class AzureStorageLinkedService(LinkedService):
    """The storage account linked service.

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
    :param connection_string: The connection string. It is mutually exclusive
     with sasUri property. Type: string, SecureString or
     AzureKeyVaultSecretReference.
    :type connection_string: object
    :param account_key: The Azure key vault secret reference of accountKey in
     connection string.
    :type account_key:
     ~azure.mgmt.datafactory.models.AzureKeyVaultSecretReference
    :param sas_uri: SAS URI of the Azure Storage resource. It is mutually
     exclusive with connectionString property. Type: string, SecureString or
     AzureKeyVaultSecretReference.
    :type sas_uri: object
    :param sas_token: The Azure key vault secret reference of sasToken in sas
     uri.
    :type sas_token:
     ~azure.mgmt.datafactory.models.AzureKeyVaultSecretReference
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'connection_string': {'key': 'typeProperties.connectionString', 'type': 'object'},
        'account_key': {'key': 'typeProperties.accountKey', 'type': 'AzureKeyVaultSecretReference'},
        'sas_uri': {'key': 'typeProperties.sasUri', 'type': 'object'},
        'sas_token': {'key': 'typeProperties.sasToken', 'type': 'AzureKeyVaultSecretReference'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AzureStorageLinkedService, self).__init__(**kwargs)
        self.connection_string = kwargs.get('connection_string', None)
        self.account_key = kwargs.get('account_key', None)
        self.sas_uri = kwargs.get('sas_uri', None)
        self.sas_token = kwargs.get('sas_token', None)
        self.encrypted_credential = kwargs.get('encrypted_credential', None)
        self.type = 'AzureStorage'
