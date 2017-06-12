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


class UpdateEncryptionConfig(Model):
    """The encryption configuration used to update a user managed Key Vault key.

    :param key_vault_meta_info: The updated Key Vault key to use in user
     managed key rotation.
    :type key_vault_meta_info: :class:`UpdateKeyVaultMetaInfo
     <azure.mgmt.datalake.store.models.UpdateKeyVaultMetaInfo>`
    """

    _attribute_map = {
        'key_vault_meta_info': {'key': 'keyVaultMetaInfo', 'type': 'UpdateKeyVaultMetaInfo'},
    }

    def __init__(self, key_vault_meta_info=None):
        self.key_vault_meta_info = key_vault_meta_info
