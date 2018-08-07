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


class AzureBatchLinkedService(LinkedService):
    """Azure Batch linked service.

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
    :param type: Constant filled by server.
    :type type: str
    :param account_name: The Azure Batch account name. Type: string (or
     Expression with resultType string).
    :type account_name: object
    :param access_key: The Azure Batch account access key.
    :type access_key: ~azure.mgmt.datafactory.models.SecretBase
    :param batch_uri: The Azure Batch URI. Type: string (or Expression with
     resultType string).
    :type batch_uri: object
    :param pool_name: The Azure Batch pool name. Type: string (or Expression
     with resultType string).
    :type pool_name: object
    :param linked_service_name: The Azure Storage linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'account_name': {'required': True},
        'batch_uri': {'required': True},
        'pool_name': {'required': True},
        'linked_service_name': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'account_name': {'key': 'typeProperties.accountName', 'type': 'object'},
        'access_key': {'key': 'typeProperties.accessKey', 'type': 'SecretBase'},
        'batch_uri': {'key': 'typeProperties.batchUri', 'type': 'object'},
        'pool_name': {'key': 'typeProperties.poolName', 'type': 'object'},
        'linked_service_name': {'key': 'typeProperties.linkedServiceName', 'type': 'LinkedServiceReference'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, account_name, batch_uri, pool_name, linked_service_name, additional_properties=None, connect_via=None, description=None, parameters=None, annotations=None, access_key=None, encrypted_credential=None):
        super(AzureBatchLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations)
        self.account_name = account_name
        self.access_key = access_key
        self.batch_uri = batch_uri
        self.pool_name = pool_name
        self.linked_service_name = linked_service_name
        self.encrypted_credential = encrypted_credential
        self.type = 'AzureBatch'
