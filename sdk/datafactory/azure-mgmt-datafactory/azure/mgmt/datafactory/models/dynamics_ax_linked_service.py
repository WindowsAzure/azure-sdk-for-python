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


class DynamicsAXLinkedService(LinkedService):
    """Dynamics AX linked service.

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
    :param url: Required. The Dynamics AX (or Dynamics 365 Finance and
     Operations) instance OData endpoint.
    :type url: object
    :param service_principal_id: Required. Specify the application's client
     ID. Type: string (or Expression with resultType string).
    :type service_principal_id: object
    :param service_principal_key: Required. Specify the application's key.
     Mark this field as a SecureString to store it securely in Data Factory, or
     reference a secret stored in Azure Key Vault. Type: string (or Expression
     with resultType string).
    :type service_principal_key: ~azure.mgmt.datafactory.models.SecretBase
    :param tenant: Required. Specify the tenant information (domain name or
     tenant ID) under which your application resides. Retrieve it by hovering
     the mouse in the top-right corner of the Azure portal. Type: string (or
     Expression with resultType string).
    :type tenant: object
    :param aad_resource_id: Required. Specify the resource you are requesting
     authorization. Type: string (or Expression with resultType string).
    :type aad_resource_id: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'url': {'required': True},
        'service_principal_id': {'required': True},
        'service_principal_key': {'required': True},
        'tenant': {'required': True},
        'aad_resource_id': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'url': {'key': 'typeProperties.url', 'type': 'object'},
        'service_principal_id': {'key': 'typeProperties.servicePrincipalId', 'type': 'object'},
        'service_principal_key': {'key': 'typeProperties.servicePrincipalKey', 'type': 'SecretBase'},
        'tenant': {'key': 'typeProperties.tenant', 'type': 'object'},
        'aad_resource_id': {'key': 'typeProperties.aadResourceId', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(DynamicsAXLinkedService, self).__init__(**kwargs)
        self.url = kwargs.get('url', None)
        self.service_principal_id = kwargs.get('service_principal_id', None)
        self.service_principal_key = kwargs.get('service_principal_key', None)
        self.tenant = kwargs.get('tenant', None)
        self.aad_resource_id = kwargs.get('aad_resource_id', None)
        self.encrypted_credential = kwargs.get('encrypted_credential', None)
        self.type = 'DynamicsAX'
