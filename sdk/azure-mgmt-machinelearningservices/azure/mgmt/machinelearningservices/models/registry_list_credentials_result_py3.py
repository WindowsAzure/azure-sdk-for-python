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


class RegistryListCredentialsResult(Model):
    """RegistryListCredentialsResult.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar location:
    :vartype location: str
    :ivar username:
    :vartype username: str
    :param passwords:
    :type passwords: list[~azure.mgmt.machinelearningservices.models.Password]
    """

    _validation = {
        'location': {'readonly': True},
        'username': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'username': {'key': 'username', 'type': 'str'},
        'passwords': {'key': 'passwords', 'type': '[Password]'},
    }

    def __init__(self, *, passwords=None, **kwargs) -> None:
        super(RegistryListCredentialsResult, self).__init__(**kwargs)
        self.location = None
        self.username = None
        self.passwords = passwords
