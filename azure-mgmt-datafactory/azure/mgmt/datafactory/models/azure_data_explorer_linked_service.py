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


class AzureDataExplorerLinkedService(LinkedService):
    """Azure Data Explorer (Kusto) linked service.

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
    :param endpoint: Required. The endpoint of Azure Data Explorer (the
     engine's endpoint). URL will be in the format
     https://<clusterName>.<regionName>.kusto.windows.net. Type: string (or
     Expression with resultType string)
    :type endpoint: object
    :param service_principal_id: Required. The ID of the service principal
     used to authenticate against Azure Data Explorer. Type: string (or
     Expression with resultType string).
    :type service_principal_id: object
    :param service_principal_key: Required. The key of the service principal
     used to authenticate against Kusto.
    :type service_principal_key: ~azure.mgmt.datafactory.models.SecretBase
    :param database: Required. Database name for connection. Type: string (or
     Expression with resultType string).
    :type database: object
    :param tenant: Required. The name or ID of the tenant to which the service
     principal belongs. Type: string (or Expression with resultType string).
    :type tenant: object
    """

    _validation = {
        'type': {'required': True},
        'endpoint': {'required': True},
        'service_principal_id': {'required': True},
        'service_principal_key': {'required': True},
        'database': {'required': True},
        'tenant': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'endpoint': {'key': 'typeProperties.endpoint', 'type': 'object'},
        'service_principal_id': {'key': 'typeProperties.servicePrincipalId', 'type': 'object'},
        'service_principal_key': {'key': 'typeProperties.servicePrincipalKey', 'type': 'SecretBase'},
        'database': {'key': 'typeProperties.database', 'type': 'object'},
        'tenant': {'key': 'typeProperties.tenant', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(AzureDataExplorerLinkedService, self).__init__(**kwargs)
        self.endpoint = kwargs.get('endpoint', None)
        self.service_principal_id = kwargs.get('service_principal_id', None)
        self.service_principal_key = kwargs.get('service_principal_key', None)
        self.database = kwargs.get('database', None)
        self.tenant = kwargs.get('tenant', None)
        self.type = 'AzureDataExplorer'
