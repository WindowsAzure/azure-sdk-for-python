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


class StorageProfile(Model):
    """Storage Profile properties of a server.

    :param backup_retention_days: Backup retention days for the server.
    :type backup_retention_days: int
    :param geo_redundant_backup: Enable Geo-redundant or not for server
     backup. Possible values include: 'Enabled', 'Disabled'
    :type geo_redundant_backup: str or
     ~azure.mgmt.rdbms.mysql.models.GeoRedundantBackup
    :param storage_mb: Max storage allowed for a server.
    :type storage_mb: int
    :param storage_autogrow: Enable Storage Auto Grow. Possible values
     include: 'Enabled', 'Disabled'
    :type storage_autogrow: str or
     ~azure.mgmt.rdbms.mysql.models.StorageAutogrow
    """

    _attribute_map = {
        'backup_retention_days': {'key': 'backupRetentionDays', 'type': 'int'},
        'geo_redundant_backup': {'key': 'geoRedundantBackup', 'type': 'str'},
        'storage_mb': {'key': 'storageMB', 'type': 'int'},
        'storage_autogrow': {'key': 'storageAutogrow', 'type': 'str'},
    }

    def __init__(self, *, backup_retention_days: int=None, geo_redundant_backup=None, storage_mb: int=None, storage_autogrow=None, **kwargs) -> None:
        super(StorageProfile, self).__init__(**kwargs)
        self.backup_retention_days = backup_retention_days
        self.geo_redundant_backup = geo_redundant_backup
        self.storage_mb = storage_mb
        self.storage_autogrow = storage_autogrow
