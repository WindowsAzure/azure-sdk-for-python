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

from .connection_info_py3 import ConnectionInfo


class MongoDbConnectionInfo(ConnectionInfo):
    """Describes a connection to a MongoDB data source.

    All required parameters must be populated in order to send to Azure.

    :param user_name: User name
    :type user_name: str
    :param password: Password credential.
    :type password: str
    :param type: Required. Constant filled by server.
    :type type: str
    :param connection_string: Required. A MongoDB connection string or blob
     container URL. The user name and password can be specified here or in the
     userName and password properties
    :type connection_string: str
    """

    _validation = {
        'type': {'required': True},
        'connection_string': {'required': True},
    }

    _attribute_map = {
        'user_name': {'key': 'userName', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'connection_string': {'key': 'connectionString', 'type': 'str'},
    }

    def __init__(self, *, connection_string: str, user_name: str=None, password: str=None, **kwargs) -> None:
        super(MongoDbConnectionInfo, self).__init__(user_name=user_name, password=password, **kwargs)
        self.connection_string = connection_string
        self.type = 'MongoDbConnectionInfo'
