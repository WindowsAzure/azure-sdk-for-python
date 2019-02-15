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


class AzureMLLinkedService(LinkedService):
    """Azure ML Web Service linked service.

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
    :param ml_endpoint: Required. The Batch Execution REST URL for an Azure ML
     Web Service endpoint. Type: string (or Expression with resultType string).
    :type ml_endpoint: object
    :param api_key: Required. The API key for accessing the Azure ML model
     endpoint.
    :type api_key: ~azure.mgmt.datafactory.models.SecretBase
    :param update_resource_endpoint: The Update Resource REST URL for an Azure
     ML Web Service endpoint. Type: string (or Expression with resultType
     string).
    :type update_resource_endpoint: object
    :param service_principal_id: The ID of the service principal used to
     authenticate against the ARM-based updateResourceEndpoint of an Azure ML
     web service. Type: string (or Expression with resultType string).
    :type service_principal_id: object
    :param service_principal_key: The key of the service principal used to
     authenticate against the ARM-based updateResourceEndpoint of an Azure ML
     web service.
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
        'ml_endpoint': {'required': True},
        'api_key': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'ml_endpoint': {'key': 'typeProperties.mlEndpoint', 'type': 'object'},
        'api_key': {'key': 'typeProperties.apiKey', 'type': 'SecretBase'},
        'update_resource_endpoint': {'key': 'typeProperties.updateResourceEndpoint', 'type': 'object'},
        'service_principal_id': {'key': 'typeProperties.servicePrincipalId', 'type': 'object'},
        'service_principal_key': {'key': 'typeProperties.servicePrincipalKey', 'type': 'SecretBase'},
        'tenant': {'key': 'typeProperties.tenant', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, *, ml_endpoint, api_key, additional_properties=None, connect_via=None, description: str=None, parameters=None, annotations=None, update_resource_endpoint=None, service_principal_id=None, service_principal_key=None, tenant=None, encrypted_credential=None, **kwargs) -> None:
        super(AzureMLLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations, **kwargs)
        self.ml_endpoint = ml_endpoint
        self.api_key = api_key
        self.update_resource_endpoint = update_resource_endpoint
        self.service_principal_id = service_principal_id
        self.service_principal_key = service_principal_key
        self.tenant = tenant
        self.encrypted_credential = encrypted_credential
        self.type = 'AzureML'
