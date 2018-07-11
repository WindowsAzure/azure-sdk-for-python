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


class UpdateKeyVaultMetaInfo(Model):
    """The Key Vault update information used for user managed key rotation.

    :param encryption_key_version: The version of the user managed encryption
     key to update through a key rotation.
    :type encryption_key_version: str
    """

    _attribute_map = {
        'encryption_key_version': {'key': 'encryptionKeyVersion', 'type': 'str'},
    }

    def __init__(self, *, encryption_key_version: str=None, **kwargs) -> None:
        super(UpdateKeyVaultMetaInfo, self).__init__(**kwargs)
        self.encryption_key_version = encryption_key_version
