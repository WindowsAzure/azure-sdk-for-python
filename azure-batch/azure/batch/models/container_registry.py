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


class ContainerRegistry(Model):
    """A private container registry.

    :param registry_server: The registry URL. If omitted, the default is
     "docker.io".
    :type registry_server: str
    :param user_name: The user name to log into the registry server.
    :type user_name: str
    :param password: The password to log into the registry server.
    :type password: str
    """

    _validation = {
        'user_name': {'required': True},
        'password': {'required': True},
    }

    _attribute_map = {
        'registry_server': {'key': 'registryServer', 'type': 'str'},
        'user_name': {'key': 'username', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
    }

    def __init__(self, user_name, password, registry_server=None):
        super(ContainerRegistry, self).__init__()
        self.registry_server = registry_server
        self.user_name = user_name
        self.password = password
