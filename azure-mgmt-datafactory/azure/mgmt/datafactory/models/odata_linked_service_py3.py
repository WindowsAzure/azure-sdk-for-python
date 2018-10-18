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


class ODataLinkedService(LinkedService):
    """Open Data Protocol (OData) linked service.

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
    :param url: Required. The URL of the OData service endpoint. Type: string
     (or Expression with resultType string).
    :type url: object
    :param authentication_type: Required. Type of authentication used to
     connect to the OData service. Possible values include: 'Anonymous',
     'Basic', 'Windows', 'AadServicePrincipal', 'ManagedServiceIdentity'
    :type authentication_type: str or
     ~azure.mgmt.datafactory.models.ODataAuthenticationType
    :param user_name: User name of the OData service. Type: string (or
     Expression with resultType string).
    :type user_name: object
    :param password: Password of the OData service.
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    :param tenant: Specify the tenant information (domain name or tenant ID)
     under which your application resides. Type: string (or Expression with
     resultType string).
    :type tenant: object
    :param service_principal_id: Specify the application id of your
     application registered in Azure Active Directory. Type: string (or
     Expression with resultType string).
    :type service_principal_id: object
    :param aad_resource_id: Specify the resource you are requesting
     authorization to use Directory. Type: string (or Expression with
     resultType string).
    :type aad_resource_id: object
    :param aad_service_principal_credential_type: Specify the credential type
     (key or cert) is used for service principal. Possible values include:
     'ServicePrincipalKey', 'ServicePrincipalCert'
    :type aad_service_principal_credential_type: str or
     ~azure.mgmt.datafactory.models.ODataAadServicePrincipalCredentialType
    :param service_principal_key: Specify the secret of your application
     registered in Azure Active Directory. Type: string (or Expression with
     resultType string).
    :type service_principal_key: ~azure.mgmt.datafactory.models.SecretBase
    :param service_principal_embedded_cert: Specify the base64 encoded
     certificate of your application registered in Azure Active Directory.
     Type: string (or Expression with resultType string).
    :type service_principal_embedded_cert:
     ~azure.mgmt.datafactory.models.SecretBase
    :param service_principal_embedded_cert_password: Specify the password of
     your certificate if your certificate has a password and you are using
     AadServicePrincipal authentication. Type: string (or Expression with
     resultType string).
    :type service_principal_embedded_cert_password:
     ~azure.mgmt.datafactory.models.SecretBase
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'url': {'required': True},
        'authentication_type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'url': {'key': 'typeProperties.url', 'type': 'object'},
        'authentication_type': {'key': 'typeProperties.authenticationType', 'type': 'str'},
        'user_name': {'key': 'typeProperties.userName', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecretBase'},
        'tenant': {'key': 'typeProperties.tenant', 'type': 'object'},
        'service_principal_id': {'key': 'typeProperties.servicePrincipalId', 'type': 'object'},
        'aad_resource_id': {'key': 'typeProperties.aadResourceId', 'type': 'object'},
        'aad_service_principal_credential_type': {'key': 'typeProperties.aadServicePrincipalCredentialType', 'type': 'str'},
        'service_principal_key': {'key': 'typeProperties.servicePrincipalKey', 'type': 'SecretBase'},
        'service_principal_embedded_cert': {'key': 'typeProperties.servicePrincipalEmbeddedCert', 'type': 'SecretBase'},
        'service_principal_embedded_cert_password': {'key': 'typeProperties.servicePrincipalEmbeddedCertPassword', 'type': 'SecretBase'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, *, url, authentication_type, additional_properties=None, connect_via=None, description: str=None, parameters=None, annotations=None, user_name=None, password=None, tenant=None, service_principal_id=None, aad_resource_id=None, aad_service_principal_credential_type=None, service_principal_key=None, service_principal_embedded_cert=None, service_principal_embedded_cert_password=None, encrypted_credential=None, **kwargs) -> None:
        super(ODataLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations, **kwargs)
        self.url = url
        self.authentication_type = authentication_type
        self.user_name = user_name
        self.password = password
        self.tenant = tenant
        self.service_principal_id = service_principal_id
        self.aad_resource_id = aad_resource_id
        self.aad_service_principal_credential_type = aad_service_principal_credential_type
        self.service_principal_key = service_principal_key
        self.service_principal_embedded_cert = service_principal_embedded_cert
        self.service_principal_embedded_cert_password = service_principal_embedded_cert_password
        self.encrypted_credential = encrypted_credential
        self.type = 'OData'
