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


class BackupEngineExtendedInfo(Model):
    """Additional information on backup engine.

    :param database_name: Database name of backup engine.
    :type database_name: str
    :param protected_items_count: Number of protected items in the backup
     engine.
    :type protected_items_count: int
    :param protected_servers_count: Number of protected servers in the backup
     engine.
    :type protected_servers_count: int
    :param disk_count: Number of disks in the backup engine.
    :type disk_count: int
    :param used_disk_space: Disk space used in the backup engine.
    :type used_disk_space: float
    :param available_disk_space: Disk space currently available in the backup
     engine.
    :type available_disk_space: float
    :param refreshed_at: Last refresh time in the backup engine.
    :type refreshed_at: datetime
    :param azure_protected_instances: Protected instances in the backup
     engine.
    :type azure_protected_instances: int
    """

    _attribute_map = {
        'database_name': {'key': 'databaseName', 'type': 'str'},
        'protected_items_count': {'key': 'protectedItemsCount', 'type': 'int'},
        'protected_servers_count': {'key': 'protectedServersCount', 'type': 'int'},
        'disk_count': {'key': 'diskCount', 'type': 'int'},
        'used_disk_space': {'key': 'usedDiskSpace', 'type': 'float'},
        'available_disk_space': {'key': 'availableDiskSpace', 'type': 'float'},
        'refreshed_at': {'key': 'refreshedAt', 'type': 'iso-8601'},
        'azure_protected_instances': {'key': 'azureProtectedInstances', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(BackupEngineExtendedInfo, self).__init__(**kwargs)
        self.database_name = kwargs.get('database_name', None)
        self.protected_items_count = kwargs.get('protected_items_count', None)
        self.protected_servers_count = kwargs.get('protected_servers_count', None)
        self.disk_count = kwargs.get('disk_count', None)
        self.used_disk_space = kwargs.get('used_disk_space', None)
        self.available_disk_space = kwargs.get('available_disk_space', None)
        self.refreshed_at = kwargs.get('refreshed_at', None)
        self.azure_protected_instances = kwargs.get('azure_protected_instances', None)
