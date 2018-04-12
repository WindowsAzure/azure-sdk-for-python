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

from .backup_storage_description import BackupStorageDescription


class FileShareBackupStorageDescription(BackupStorageDescription):
    """Describes the parameters for file share storage used for storing or
    enumerating backups.

    All required parameters must be populated in order to send to Azure.

    :param friendly_name: Friendly name for this backup storage.
    :type friendly_name: str
    :param storage_kind: Required. Constant filled by server.
    :type storage_kind: str
    :param path: Required. UNC path of the file share where to store or
     enumerate backups from.
    :type path: str
    :param primary_user_name: Primary user name to access the file share.
    :type primary_user_name: str
    :param primary_password: Primary password to access the share location.
    :type primary_password: str
    :param secondary_user_name: Secondary user name to access the file share.
    :type secondary_user_name: str
    :param secondary_password: Secondary password to access the share location
    :type secondary_password: str
    """

    _validation = {
        'storage_kind': {'required': True},
        'path': {'required': True},
    }

    _attribute_map = {
        'friendly_name': {'key': 'FriendlyName', 'type': 'str'},
        'storage_kind': {'key': 'StorageKind', 'type': 'str'},
        'path': {'key': 'Path', 'type': 'str'},
        'primary_user_name': {'key': 'PrimaryUserName', 'type': 'str'},
        'primary_password': {'key': 'PrimaryPassword', 'type': 'str'},
        'secondary_user_name': {'key': 'SecondaryUserName', 'type': 'str'},
        'secondary_password': {'key': 'SecondaryPassword', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(FileShareBackupStorageDescription, self).__init__(**kwargs)
        self.path = kwargs.get('path', None)
        self.primary_user_name = kwargs.get('primary_user_name', None)
        self.primary_password = kwargs.get('primary_password', None)
        self.secondary_user_name = kwargs.get('secondary_user_name', None)
        self.secondary_password = kwargs.get('secondary_password', None)
        self.storage_kind = 'FileShare'
