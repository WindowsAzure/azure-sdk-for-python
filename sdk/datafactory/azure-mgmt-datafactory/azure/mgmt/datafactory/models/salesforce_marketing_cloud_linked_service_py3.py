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


class SalesforceMarketingCloudLinkedService(LinkedService):
    """Salesforce Marketing Cloud linked service.

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
    :param client_id: Required. The client ID associated with the Salesforce
     Marketing Cloud application. Type: string (or Expression with resultType
     string).
    :type client_id: object
    :param client_secret: The client secret associated with the Salesforce
     Marketing Cloud application. Type: string (or Expression with resultType
     string).
    :type client_secret: ~azure.mgmt.datafactory.models.SecretBase
    :param use_encrypted_endpoints: Specifies whether the data source
     endpoints are encrypted using HTTPS. The default value is true. Type:
     boolean (or Expression with resultType boolean).
    :type use_encrypted_endpoints: object
    :param use_host_verification: Specifies whether to require the host name
     in the server's certificate to match the host name of the server when
     connecting over SSL. The default value is true. Type: boolean (or
     Expression with resultType boolean).
    :type use_host_verification: object
    :param use_peer_verification: Specifies whether to verify the identity of
     the server when connecting over SSL. The default value is true. Type:
     boolean (or Expression with resultType boolean).
    :type use_peer_verification: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'client_id': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'client_id': {'key': 'typeProperties.clientId', 'type': 'object'},
        'client_secret': {'key': 'typeProperties.clientSecret', 'type': 'SecretBase'},
        'use_encrypted_endpoints': {'key': 'typeProperties.useEncryptedEndpoints', 'type': 'object'},
        'use_host_verification': {'key': 'typeProperties.useHostVerification', 'type': 'object'},
        'use_peer_verification': {'key': 'typeProperties.usePeerVerification', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, *, client_id, additional_properties=None, connect_via=None, description: str=None, parameters=None, annotations=None, client_secret=None, use_encrypted_endpoints=None, use_host_verification=None, use_peer_verification=None, encrypted_credential=None, **kwargs) -> None:
        super(SalesforceMarketingCloudLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations, **kwargs)
        self.client_id = client_id
        self.client_secret = client_secret
        self.use_encrypted_endpoints = use_encrypted_endpoints
        self.use_host_verification = use_host_verification
        self.use_peer_verification = use_peer_verification
        self.encrypted_credential = encrypted_credential
        self.type = 'SalesforceMarketingCloud'
