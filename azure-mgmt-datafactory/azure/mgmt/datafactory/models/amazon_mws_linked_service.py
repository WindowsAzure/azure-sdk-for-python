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


class AmazonMWSLinkedService(LinkedService):
    """Amazon Marketplace Web Service linked service.

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
    :param endpoint: The endpoint of the Amazon MWS server, (i.e.
     mws.amazonservices.com)
    :type endpoint: object
    :param marketplace_id: The Amazon Marketplace ID you want to retrieve data
     from. To retrive data from multiple Marketplace IDs, separate them with a
     comma (,). (i.e. A2EUQ1WTGCTBG2)
    :type marketplace_id: object
    :param seller_id: The Amazon seller ID.
    :type seller_id: object
    :param mws_auth_token: The Amazon MWS authentication token.
    :type mws_auth_token: ~azure.mgmt.datafactory.models.SecretBase
    :param access_key_id: The access key id used to access data.
    :type access_key_id: object
    :param secret_key: The secret key used to access data.
    :type secret_key: ~azure.mgmt.datafactory.models.SecretBase
    :param use_encrypted_endpoints: Specifies whether the data source
     endpoints are encrypted using HTTPS. The default value is true.
    :type use_encrypted_endpoints: object
    :param use_host_verification: Specifies whether to require the host name
     in the server's certificate to match the host name of the server when
     connecting over SSL. The default value is true.
    :type use_host_verification: object
    :param use_peer_verification: Specifies whether to verify the identity of
     the server when connecting over SSL. The default value is true.
    :type use_peer_verification: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'endpoint': {'required': True},
        'marketplace_id': {'required': True},
        'seller_id': {'required': True},
        'access_key_id': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'endpoint': {'key': 'typeProperties.endpoint', 'type': 'object'},
        'marketplace_id': {'key': 'typeProperties.marketplaceID', 'type': 'object'},
        'seller_id': {'key': 'typeProperties.sellerID', 'type': 'object'},
        'mws_auth_token': {'key': 'typeProperties.mwsAuthToken', 'type': 'SecretBase'},
        'access_key_id': {'key': 'typeProperties.accessKeyId', 'type': 'object'},
        'secret_key': {'key': 'typeProperties.secretKey', 'type': 'SecretBase'},
        'use_encrypted_endpoints': {'key': 'typeProperties.useEncryptedEndpoints', 'type': 'object'},
        'use_host_verification': {'key': 'typeProperties.useHostVerification', 'type': 'object'},
        'use_peer_verification': {'key': 'typeProperties.usePeerVerification', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, endpoint, marketplace_id, seller_id, access_key_id, additional_properties=None, connect_via=None, description=None, parameters=None, annotations=None, mws_auth_token=None, secret_key=None, use_encrypted_endpoints=None, use_host_verification=None, use_peer_verification=None, encrypted_credential=None):
        super(AmazonMWSLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations)
        self.endpoint = endpoint
        self.marketplace_id = marketplace_id
        self.seller_id = seller_id
        self.mws_auth_token = mws_auth_token
        self.access_key_id = access_key_id
        self.secret_key = secret_key
        self.use_encrypted_endpoints = use_encrypted_endpoints
        self.use_host_verification = use_host_verification
        self.use_peer_verification = use_peer_verification
        self.encrypted_credential = encrypted_credential
        self.type = 'AmazonMWS'
