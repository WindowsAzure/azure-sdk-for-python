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


class StorageAccountKey(Model):
    """An access key for the storage account.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar key_name: Name of the key.
    :vartype key_name: str
    :ivar value: Base 64-encoded value of the key.
    :vartype value: str
    :ivar permissions: Permissions for the key -- read-only or full
     permissions. Possible values include: 'Read', 'Full'
    :vartype permissions: str or
     ~azure.mgmt.storage.v2019_04_01.models.KeyPermission
    """

    _validation = {
        'key_name': {'readonly': True},
        'value': {'readonly': True},
        'permissions': {'readonly': True},
    }

    _attribute_map = {
        'key_name': {'key': 'keyName', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
        'permissions': {'key': 'permissions', 'type': 'KeyPermission'},
    }

    def __init__(self, **kwargs) -> None:
        super(StorageAccountKey, self).__init__(**kwargs)
        self.key_name = None
        self.value = None
        self.permissions = None
