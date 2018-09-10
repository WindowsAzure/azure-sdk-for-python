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

from .connection_info import ConnectionInfo


class SqlConnectionInfo(ConnectionInfo):
    """Information for connecting to SQL database server.

    All required parameters must be populated in order to send to Azure.

    :param user_name: User name
    :type user_name: str
    :param password: Password credential.
    :type password: str
    :param type: Required. Constant filled by server.
    :type type: str
    :param data_source: Required. Data source in the format
     Protocol:MachineName\\SQLServerInstanceName,PortNumber
    :type data_source: str
    :param authentication: Authentication type to use for connection. Possible
     values include: 'None', 'WindowsAuthentication', 'SqlAuthentication',
     'ActiveDirectoryIntegrated', 'ActiveDirectoryPassword'
    :type authentication: str or
     ~azure.mgmt.datamigration.models.AuthenticationType
    :param encrypt_connection: Whether to encrypt the connection. Default
     value: True .
    :type encrypt_connection: bool
    :param additional_settings: Additional connection settings
    :type additional_settings: str
    :param trust_server_certificate: Whether to trust the server certificate.
     Default value: False .
    :type trust_server_certificate: bool
    :param platform: Server platform type for connection. Possible values
     include: 'SqlOnPrem'
    :type platform: str or ~azure.mgmt.datamigration.models.SqlSourcePlatform
    """

    _validation = {
        'type': {'required': True},
        'data_source': {'required': True},
    }

    _attribute_map = {
        'user_name': {'key': 'userName', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'data_source': {'key': 'dataSource', 'type': 'str'},
        'authentication': {'key': 'authentication', 'type': 'str'},
        'encrypt_connection': {'key': 'encryptConnection', 'type': 'bool'},
        'additional_settings': {'key': 'additionalSettings', 'type': 'str'},
        'trust_server_certificate': {'key': 'trustServerCertificate', 'type': 'bool'},
        'platform': {'key': 'platform', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SqlConnectionInfo, self).__init__(**kwargs)
        self.data_source = kwargs.get('data_source', None)
        self.authentication = kwargs.get('authentication', None)
        self.encrypt_connection = kwargs.get('encrypt_connection', True)
        self.additional_settings = kwargs.get('additional_settings', None)
        self.trust_server_certificate = kwargs.get('trust_server_certificate', False)
        self.platform = kwargs.get('platform', None)
        self.type = 'SqlConnectionInfo'
