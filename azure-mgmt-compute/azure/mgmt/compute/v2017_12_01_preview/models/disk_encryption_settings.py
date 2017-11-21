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


class DiskEncryptionSettings(Model):
    """Describes a Encryption Settings for a Disk.

    :param disk_encryption_key: Specifies the location of the disk encryption
     key, which is a Key Vault Secret.
    :type disk_encryption_key:
     ~azure.mgmt.compute.v2017_12_01_preview.models.KeyVaultSecretReference
    :param key_encryption_key: Specifies the location of the key encryption
     key in Key Vault.
    :type key_encryption_key:
     ~azure.mgmt.compute.v2017_12_01_preview.models.KeyVaultKeyReference
    :param enabled: Specifies whether disk encryption should be enabled on the
     virtual machine.
    :type enabled: bool
    """

    _attribute_map = {
        'disk_encryption_key': {'key': 'diskEncryptionKey', 'type': 'KeyVaultSecretReference'},
        'key_encryption_key': {'key': 'keyEncryptionKey', 'type': 'KeyVaultKeyReference'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
    }

    def __init__(self, disk_encryption_key=None, key_encryption_key=None, enabled=None):
        self.disk_encryption_key = disk_encryption_key
        self.key_encryption_key = key_encryption_key
        self.enabled = enabled
