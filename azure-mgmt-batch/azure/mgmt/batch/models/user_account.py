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


class UserAccount(Model):
    """Properties used to create a user on an Azure Batch node.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the user account.
    :type name: str
    :param password: Required. The password for the user account.
    :type password: str
    :param elevation_level: The elevation level of the user account. nonAdmin
     - The auto user is a standard user without elevated access. admin - The
     auto user is a user with elevated access and operates with full
     Administrator permissions. The default value is nonAdmin. Possible values
     include: 'NonAdmin', 'Admin'
    :type elevation_level: str or ~azure.mgmt.batch.models.ElevationLevel
    :param linux_user_configuration: The Linux-specific user configuration for
     the user account. This property is ignored if specified on a Windows pool.
     If not specified, the user is created with the default options.
    :type linux_user_configuration:
     ~azure.mgmt.batch.models.LinuxUserConfiguration
    """

    _validation = {
        'name': {'required': True},
        'password': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
        'elevation_level': {'key': 'elevationLevel', 'type': 'ElevationLevel'},
        'linux_user_configuration': {'key': 'linuxUserConfiguration', 'type': 'LinuxUserConfiguration'},
    }

    def __init__(self, **kwargs):
        super(UserAccount, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.password = kwargs.get('password', None)
        self.elevation_level = kwargs.get('elevation_level', None)
        self.linux_user_configuration = kwargs.get('linux_user_configuration', None)
