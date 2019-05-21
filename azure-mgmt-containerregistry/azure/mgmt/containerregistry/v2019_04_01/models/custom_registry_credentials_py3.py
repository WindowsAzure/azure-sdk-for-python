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


class CustomRegistryCredentials(Model):
    """Describes the credentials that will be used to access a custom registry
    during a run.

    :param user_name: The username for logging into the custom registry.
    :type user_name:
     ~azure.mgmt.containerregistry.v2019_04_01.models.SecretObject
    :param password: The password for logging into the custom registry. The
     password is a secret
     object that allows multiple ways of providing the value for it.
    :type password:
     ~azure.mgmt.containerregistry.v2019_04_01.models.SecretObject
    :param identity: Indicates the managed identity assigned to the custom
     credential. If a user-assigned identity
     this value is the Client ID. If a system-assigned identity, the value will
     be `system`. In
     the case of a system-assigned identity, the Client ID will be determined
     by the runner. This
     identity may be used to authenticate to key vault to retrieve credentials
     or it may be the only
     source of authentication used for accessing the registry.
    :type identity: str
    """

    _attribute_map = {
        'user_name': {'key': 'userName', 'type': 'SecretObject'},
        'password': {'key': 'password', 'type': 'SecretObject'},
        'identity': {'key': 'identity', 'type': 'str'},
    }

    def __init__(self, *, user_name=None, password=None, identity: str=None, **kwargs) -> None:
        super(CustomRegistryCredentials, self).__init__(**kwargs)
        self.user_name = user_name
        self.password = password
        self.identity = identity
