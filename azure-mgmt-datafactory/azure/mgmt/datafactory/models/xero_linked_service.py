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


class XeroLinkedService(LinkedService):
    """Xero Serivce linked service.

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
    :param host: The endpoint of the Xero server. (i.e. api.xero.com)
    :type host: object
    :param consumer_key: The consumer key associated with the Xero
     application.
    :type consumer_key: ~azure.mgmt.datafactory.models.SecretBase
    :param private_key: The private key from the .pem file that was generated
     for your Xero private application. You must include all the text from the
     .pem file, including the Unix line endings(
     ).
    :type private_key: ~azure.mgmt.datafactory.models.SecretBase
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
        'host': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'host': {'key': 'typeProperties.host', 'type': 'object'},
        'consumer_key': {'key': 'typeProperties.consumerKey', 'type': 'SecretBase'},
        'private_key': {'key': 'typeProperties.privateKey', 'type': 'SecretBase'},
        'use_encrypted_endpoints': {'key': 'typeProperties.useEncryptedEndpoints', 'type': 'object'},
        'use_host_verification': {'key': 'typeProperties.useHostVerification', 'type': 'object'},
        'use_peer_verification': {'key': 'typeProperties.usePeerVerification', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, host, additional_properties=None, connect_via=None, description=None, parameters=None, annotations=None, consumer_key=None, private_key=None, use_encrypted_endpoints=None, use_host_verification=None, use_peer_verification=None, encrypted_credential=None):
        super(XeroLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations)
        self.host = host
        self.consumer_key = consumer_key
        self.private_key = private_key
        self.use_encrypted_endpoints = use_encrypted_endpoints
        self.use_host_verification = use_host_verification
        self.use_peer_verification = use_peer_verification
        self.encrypted_credential = encrypted_credential
        self.type = 'Xero'
