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


class QuickBooksLinkedService(LinkedService):
    """QuickBooks server linked service.

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
    :param endpoint: Required. The endpoint of the QuickBooks server. (i.e.
     quickbooks.api.intuit.com)
    :type endpoint: object
    :param company_id: Required. The company ID of the QuickBooks company to
     authorize.
    :type company_id: object
    :param consumer_key: Required. The consumer key for OAuth 1.0
     authentication.
    :type consumer_key: object
    :param consumer_secret: Required. The consumer secret for OAuth 1.0
     authentication.
    :type consumer_secret: ~azure.mgmt.datafactory.models.SecretBase
    :param access_token: Required. The access token for OAuth 1.0
     authentication.
    :type access_token: ~azure.mgmt.datafactory.models.SecretBase
    :param access_token_secret: Required. The access token secret for OAuth
     1.0 authentication.
    :type access_token_secret: ~azure.mgmt.datafactory.models.SecretBase
    :param use_encrypted_endpoints: Specifies whether the data source
     endpoints are encrypted using HTTPS. The default value is true.
    :type use_encrypted_endpoints: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'endpoint': {'required': True},
        'company_id': {'required': True},
        'consumer_key': {'required': True},
        'consumer_secret': {'required': True},
        'access_token': {'required': True},
        'access_token_secret': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'endpoint': {'key': 'typeProperties.endpoint', 'type': 'object'},
        'company_id': {'key': 'typeProperties.companyId', 'type': 'object'},
        'consumer_key': {'key': 'typeProperties.consumerKey', 'type': 'object'},
        'consumer_secret': {'key': 'typeProperties.consumerSecret', 'type': 'SecretBase'},
        'access_token': {'key': 'typeProperties.accessToken', 'type': 'SecretBase'},
        'access_token_secret': {'key': 'typeProperties.accessTokenSecret', 'type': 'SecretBase'},
        'use_encrypted_endpoints': {'key': 'typeProperties.useEncryptedEndpoints', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(QuickBooksLinkedService, self).__init__(**kwargs)
        self.endpoint = kwargs.get('endpoint', None)
        self.company_id = kwargs.get('company_id', None)
        self.consumer_key = kwargs.get('consumer_key', None)
        self.consumer_secret = kwargs.get('consumer_secret', None)
        self.access_token = kwargs.get('access_token', None)
        self.access_token_secret = kwargs.get('access_token_secret', None)
        self.use_encrypted_endpoints = kwargs.get('use_encrypted_endpoints', None)
        self.encrypted_credential = kwargs.get('encrypted_credential', None)
        self.type = 'QuickBooks'
