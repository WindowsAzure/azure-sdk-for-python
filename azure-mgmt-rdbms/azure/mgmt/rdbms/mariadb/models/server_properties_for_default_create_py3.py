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

from .server_properties_for_create_py3 import ServerPropertiesForCreate


class ServerPropertiesForDefaultCreate(ServerPropertiesForCreate):
    """The properties used to create a new server.

    All required parameters must be populated in order to send to Azure.

    :param version: Server version. Possible values include: '5.6', '5.7'
    :type version: str or ~azure.mgmt.rdbms.mariadb.models.ServerVersion
    :param ssl_enforcement: Enable ssl enforcement or not when connect to
     server. Possible values include: 'Enabled', 'Disabled'
    :type ssl_enforcement: str or
     ~azure.mgmt.rdbms.mariadb.models.SslEnforcementEnum
    :param storage_profile: Storage profile of a server.
    :type storage_profile: ~azure.mgmt.rdbms.mariadb.models.StorageProfile
    :param create_mode: Required. Constant filled by server.
    :type create_mode: str
    :param administrator_login: Required. The administrator's login name of a
     server. Can only be specified when the server is being created (and is
     required for creation).
    :type administrator_login: str
    :param administrator_login_password: Required. The password of the
     administrator login.
    :type administrator_login_password: str
    """

    _validation = {
        'create_mode': {'required': True},
        'administrator_login': {'required': True},
        'administrator_login_password': {'required': True},
    }

    _attribute_map = {
        'version': {'key': 'version', 'type': 'str'},
        'ssl_enforcement': {'key': 'sslEnforcement', 'type': 'SslEnforcementEnum'},
        'storage_profile': {'key': 'storageProfile', 'type': 'StorageProfile'},
        'create_mode': {'key': 'createMode', 'type': 'str'},
        'administrator_login': {'key': 'administratorLogin', 'type': 'str'},
        'administrator_login_password': {'key': 'administratorLoginPassword', 'type': 'str'},
    }

    def __init__(self, *, administrator_login: str, administrator_login_password: str, version=None, ssl_enforcement=None, storage_profile=None, **kwargs) -> None:
        super(ServerPropertiesForDefaultCreate, self).__init__(version=version, ssl_enforcement=ssl_enforcement, storage_profile=storage_profile, **kwargs)
        self.administrator_login = administrator_login
        self.administrator_login_password = administrator_login_password
        self.create_mode = 'Default'
