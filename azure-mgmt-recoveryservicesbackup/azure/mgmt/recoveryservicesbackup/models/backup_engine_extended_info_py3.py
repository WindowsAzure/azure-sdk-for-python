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

    def __init__(self, *, database_name: str=None, protected_items_count: int=None, protected_servers_count: int=None, disk_count: int=None, used_disk_space: float=None, available_disk_space: float=None, refreshed_at=None, azure_protected_instances: int=None, **kwargs) -> None:
        super(BackupEngineExtendedInfo, self).__init__(**kwargs)
        self.database_name = database_name
        self.protected_items_count = protected_items_count
        self.protected_servers_count = protected_servers_count
        self.disk_count = disk_count
        self.used_disk_space = used_disk_space
        self.available_disk_space = available_disk_space
        self.refreshed_at = refreshed_at
        self.azure_protected_instances = azure_protected_instances
