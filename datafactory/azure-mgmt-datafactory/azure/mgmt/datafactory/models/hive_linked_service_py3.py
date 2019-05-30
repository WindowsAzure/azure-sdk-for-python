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


class HiveLinkedService(LinkedService):
    """Hive Server linked service.

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
    :param host: Required. IP address or host name of the Hive server,
     separated by ';' for multiple hosts (only when serviceDiscoveryMode is
     enable).
    :type host: object
    :param port: The TCP port that the Hive server uses to listen for client
     connections.
    :type port: object
    :param server_type: The type of Hive server. Possible values include:
     'HiveServer1', 'HiveServer2', 'HiveThriftServer'
    :type server_type: str or ~azure.mgmt.datafactory.models.HiveServerType
    :param thrift_transport_protocol: The transport protocol to use in the
     Thrift layer. Possible values include: 'Binary', 'SASL', 'HTTP '
    :type thrift_transport_protocol: str or
     ~azure.mgmt.datafactory.models.HiveThriftTransportProtocol
    :param authentication_type: Required. The authentication method used to
     access the Hive server. Possible values include: 'Anonymous', 'Username',
     'UsernameAndPassword', 'WindowsAzureHDInsightService'
    :type authentication_type: str or
     ~azure.mgmt.datafactory.models.HiveAuthenticationType
    :param service_discovery_mode: true to indicate using the ZooKeeper
     service, false not.
    :type service_discovery_mode: object
    :param zoo_keeper_name_space: The namespace on ZooKeeper under which Hive
     Server 2 nodes are added.
    :type zoo_keeper_name_space: object
    :param use_native_query: Specifies whether the driver uses native HiveQL
     queries,or converts them into an equivalent form in HiveQL.
    :type use_native_query: object
    :param username: The user name that you use to access Hive Server.
    :type username: object
    :param password: The password corresponding to the user name that you
     provided in the Username field
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    :param http_path: The partial URL corresponding to the Hive server.
    :type http_path: object
    :param enable_ssl: Specifies whether the connections to the server are
     encrypted using SSL. The default value is false.
    :type enable_ssl: object
    :param trusted_cert_path: The full path of the .pem file containing
     trusted CA certificates for verifying the server when connecting over SSL.
     This property can only be set when using SSL on self-hosted IR. The
     default value is the cacerts.pem file installed with the IR.
    :type trusted_cert_path: object
    :param use_system_trust_store: Specifies whether to use a CA certificate
     from the system trust store or from a specified PEM file. The default
     value is false.
    :type use_system_trust_store: object
    :param allow_host_name_cn_mismatch: Specifies whether to require a
     CA-issued SSL certificate name to match the host name of the server when
     connecting over SSL. The default value is false.
    :type allow_host_name_cn_mismatch: object
    :param allow_self_signed_server_cert: Specifies whether to allow
     self-signed certificates from the server. The default value is false.
    :type allow_self_signed_server_cert: object
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    """

    _validation = {
        'type': {'required': True},
        'host': {'required': True},
        'authentication_type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'host': {'key': 'typeProperties.host', 'type': 'object'},
        'port': {'key': 'typeProperties.port', 'type': 'object'},
        'server_type': {'key': 'typeProperties.serverType', 'type': 'str'},
        'thrift_transport_protocol': {'key': 'typeProperties.thriftTransportProtocol', 'type': 'str'},
        'authentication_type': {'key': 'typeProperties.authenticationType', 'type': 'str'},
        'service_discovery_mode': {'key': 'typeProperties.serviceDiscoveryMode', 'type': 'object'},
        'zoo_keeper_name_space': {'key': 'typeProperties.zooKeeperNameSpace', 'type': 'object'},
        'use_native_query': {'key': 'typeProperties.useNativeQuery', 'type': 'object'},
        'username': {'key': 'typeProperties.username', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecretBase'},
        'http_path': {'key': 'typeProperties.httpPath', 'type': 'object'},
        'enable_ssl': {'key': 'typeProperties.enableSsl', 'type': 'object'},
        'trusted_cert_path': {'key': 'typeProperties.trustedCertPath', 'type': 'object'},
        'use_system_trust_store': {'key': 'typeProperties.useSystemTrustStore', 'type': 'object'},
        'allow_host_name_cn_mismatch': {'key': 'typeProperties.allowHostNameCNMismatch', 'type': 'object'},
        'allow_self_signed_server_cert': {'key': 'typeProperties.allowSelfSignedServerCert', 'type': 'object'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
    }

    def __init__(self, *, host, authentication_type, additional_properties=None, connect_via=None, description: str=None, parameters=None, annotations=None, port=None, server_type=None, thrift_transport_protocol=None, service_discovery_mode=None, zoo_keeper_name_space=None, use_native_query=None, username=None, password=None, http_path=None, enable_ssl=None, trusted_cert_path=None, use_system_trust_store=None, allow_host_name_cn_mismatch=None, allow_self_signed_server_cert=None, encrypted_credential=None, **kwargs) -> None:
        super(HiveLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations, **kwargs)
        self.host = host
        self.port = port
        self.server_type = server_type
        self.thrift_transport_protocol = thrift_transport_protocol
        self.authentication_type = authentication_type
        self.service_discovery_mode = service_discovery_mode
        self.zoo_keeper_name_space = zoo_keeper_name_space
        self.use_native_query = use_native_query
        self.username = username
        self.password = password
        self.http_path = http_path
        self.enable_ssl = enable_ssl
        self.trusted_cert_path = trusted_cert_path
        self.use_system_trust_store = use_system_trust_store
        self.allow_host_name_cn_mismatch = allow_host_name_cn_mismatch
        self.allow_self_signed_server_cert = allow_self_signed_server_cert
        self.encrypted_credential = encrypted_credential
        self.type = 'Hive'
