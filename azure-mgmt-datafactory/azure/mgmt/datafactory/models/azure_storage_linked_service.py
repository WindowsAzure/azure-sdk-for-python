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
    :param connection_string: The connection string. It is mutually exclusive
     with sasUri property.
    :type connection_string: ~azure.mgmt.datafactory.models.SecretBase
    :param sas_uri: SAS URI of the Azure Storage resource. It is mutually
     exclusive with connectionString property.
    :type sas_uri: ~azure.mgmt.datafactory.models.SecretBase
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'connection_string': {'key': 'typeProperties.connectionString', 'type': 'SecretBase'},
        'sas_uri': {'key': 'typeProperties.sasUri', 'type': 'SecretBase'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, additional_properties=None, connect_via=None, description=None, connection_string=None, sas_uri=None, encrypted_credential=None):
        super(AzureStorageLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description)
        self.connection_string = connection_string
        self.sas_uri = sas_uri
        self.encrypted_credential = encrypted_credential
        self.type = 'AzureStorage'
