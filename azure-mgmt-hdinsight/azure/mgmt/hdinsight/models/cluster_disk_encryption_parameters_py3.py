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


class ClusterDiskEncryptionParameters(Model):
    """The Disk Encryption Cluster request parameters.

    :param vault_uri: Base key vault URI where the customers key is located
     eg. https://myvault.vault.azure.net
    :type vault_uri: str
    :param key_name: Key name that is used for enabling disk encryption.
    :type key_name: str
    :param key_version: Specific key version that is used for enabling disk
     encryption.
    :type key_version: str
    """

    _attribute_map = {
        'vault_uri': {'key': 'vaultUri', 'type': 'str'},
        'key_name': {'key': 'keyName', 'type': 'str'},
        'key_version': {'key': 'keyVersion', 'type': 'str'},
    }

    def __init__(self, *, vault_uri: str=None, key_name: str=None, key_version: str=None, **kwargs) -> None:
        super(ClusterDiskEncryptionParameters, self).__init__(**kwargs)
        self.vault_uri = vault_uri
        self.key_name = key_name
        self.key_version = key_version
