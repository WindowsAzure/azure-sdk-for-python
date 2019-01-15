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


class ImageRegistryCredential(Model):
    """Image registry credential.

    All required parameters must be populated in order to send to Azure.

    :param server: Required. The Docker image registry server without a
     protocol such as "http" and "https".
    :type server: str
    :param username: Required. The username for the private registry.
    :type username: str
    :param password: The password for the private registry.
    :type password: str
    """

    _validation = {
        'server': {'required': True},
        'username': {'required': True},
    }

    _attribute_map = {
        'server': {'key': 'server', 'type': 'str'},
        'username': {'key': 'username', 'type': 'str'},
        'password': {'key': 'password', 'type': 'str'},
    }

    def __init__(self, *, server: str, username: str, password: str=None, **kwargs) -> None:
        super(ImageRegistryCredential, self).__init__(**kwargs)
        self.server = server
        self.username = username
        self.password = password
