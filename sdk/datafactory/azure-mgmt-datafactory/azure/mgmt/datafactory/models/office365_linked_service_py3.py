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


class Office365LinkedService(LinkedService):
    """Office365 linked service.

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
    :param office365_tenant_id: Required. Azure tenant ID to which the Office
     365 account belongs. Type: string (or Expression with resultType string).
    :type office365_tenant_id: object
    :param service_principal_tenant_id: Required. Specify the tenant
     information under which your Azure AD web application resides. Type:
     string (or Expression with resultType string).
    :type service_principal_tenant_id: object
    :param service_principal_id: Required. Specify the application's client
     ID. Type: string (or Expression with resultType string).
    :type service_principal_id: object
    :param service_principal_key: Required. Specify the application's key.
    :type service_principal_key: ~azure.mgmt.datafactory.models.SecretBase
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'office365_tenant_id': {'required': True},
        'service_principal_tenant_id': {'required': True},
        'service_principal_id': {'required': True},
        'service_principal_key': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'office365_tenant_id': {'key': 'typeProperties.office365TenantId', 'type': 'object'},
        'service_principal_tenant_id': {'key': 'typeProperties.servicePrincipalTenantId', 'type': 'object'},
        'service_principal_id': {'key': 'typeProperties.servicePrincipalId', 'type': 'object'},
        'service_principal_key': {'key': 'typeProperties.servicePrincipalKey', 'type': 'SecretBase'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, *, office365_tenant_id, service_principal_tenant_id, service_principal_id, service_principal_key, additional_properties=None, connect_via=None, description: str=None, parameters=None, annotations=None, encrypted_credential=None, **kwargs) -> None:
        super(Office365LinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations, **kwargs)
        self.office365_tenant_id = office365_tenant_id
        self.service_principal_tenant_id = service_principal_tenant_id
        self.service_principal_id = service_principal_id
        self.service_principal_key = service_principal_key
        self.encrypted_credential = encrypted_credential
        self.type = 'Office365'
