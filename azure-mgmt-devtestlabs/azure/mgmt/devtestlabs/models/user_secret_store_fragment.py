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


class UserSecretStoreFragment(Model):
    """Properties of a user's secret store.

    :param key_vault_uri: The URI of the user's Key vault.
    :type key_vault_uri: str
    :param key_vault_id: The ID of the user's Key vault.
    :type key_vault_id: str
    """

    _attribute_map = {
        'key_vault_uri': {'key': 'keyVaultUri', 'type': 'str'},
        'key_vault_id': {'key': 'keyVaultId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(UserSecretStoreFragment, self).__init__(**kwargs)
        self.key_vault_uri = kwargs.get('key_vault_uri', None)
        self.key_vault_id = kwargs.get('key_vault_id', None)
