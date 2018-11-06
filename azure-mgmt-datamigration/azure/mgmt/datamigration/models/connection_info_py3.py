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

from msrest.serialization import Model


class ConnectionInfo(Model):
    """Defines the connection properties of a server.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: PostgreSqlConnectionInfo, MySqlConnectionInfo,
    MongoDbConnectionInfo, SqlConnectionInfo

    All required parameters must be populated in order to send to Azure.

    :param user_name: User name
    :type user_name: str
    :param password: Password credential.
    :type password: str
    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'user_name': {'key': 'userName', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'PostgreSqlConnectionInfo': 'PostgreSqlConnectionInfo', 'MySqlConnectionInfo': 'MySqlConnectionInfo', 'MongoDbConnectionInfo': 'MongoDbConnectionInfo', 'SqlConnectionInfo': 'SqlConnectionInfo'}
    }

    def __init__(self, *, user_name: str=None, password: str=None, **kwargs) -> None:
        super(ConnectionInfo, self).__init__(**kwargs)
        self.user_name = user_name
        self.password = password
        self.type = None
