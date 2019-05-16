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


class EncryptionSettingsCollection(Model):
    """Encryption settings for disk or snapshot.

    All required parameters must be populated in order to send to Azure.

    :param enabled: Required. Set this flag to true and provide
     DiskEncryptionKey and optional KeyEncryptionKey to enable encryption. Set
     this flag to false and remove DiskEncryptionKey and KeyEncryptionKey to
     disable encryption. If EncryptionSettings is null in the request object,
     the existing settings remain unchanged.
    :type enabled: bool
    :param encryption_settings: A collection of encryption settings, one for
     each disk volume.
    :type encryption_settings:
     list[~azure.mgmt.compute.v2018_09_30.models.EncryptionSettingsElement]
    """

    _validation = {
        'enabled': {'required': True},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'encryption_settings': {'key': 'encryptionSettings', 'type': '[EncryptionSettingsElement]'},
    }

    def __init__(self, *, enabled: bool, encryption_settings=None, **kwargs) -> None:
        super(EncryptionSettingsCollection, self).__init__(**kwargs)
        self.enabled = enabled
        self.encryption_settings = encryption_settings
