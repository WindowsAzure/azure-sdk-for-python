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

from .resource import Resource


class BackupRequest(Resource):
    """Description of a backup which will be performed.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :param name: Resource Name.
    :type name: str
    :param kind: Kind of resource.
    :type kind: str
    :param location: Resource Location.
    :type location: str
    :param type: Resource type.
    :type type: str
    :param tags: Resource tags.
    :type tags: dict
    :param backup_request_name: Name of the backup.
    :type backup_request_name: str
    :param enabled: True if the backup schedule is enabled (must be included
     in that case), false if the backup schedule should be disabled.
    :type enabled: bool
    :param storage_account_url: SAS URL to the container.
    :type storage_account_url: str
    :param backup_schedule: Schedule for the backup if it is executed
     periodically.
    :type backup_schedule: :class:`BackupSchedule
     <azure.mgmt.web.models.BackupSchedule>`
    :param databases: Databases included in the backup.
    :type databases: list of :class:`DatabaseBackupSetting
     <azure.mgmt.web.models.DatabaseBackupSetting>`
    :param backup_request_type: Type of the backup. Possible values include:
     'Default', 'Clone', 'Relocation'
    :type backup_request_type: str or :class:`BackupRestoreOperationType
     <azure.mgmt.web.models.BackupRestoreOperationType>`
    """

    _validation = {
        'id': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'backup_request_name': {'key': 'properties.name', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'storage_account_url': {'key': 'properties.storageAccountUrl', 'type': 'str'},
        'backup_schedule': {'key': 'properties.backupSchedule', 'type': 'BackupSchedule'},
        'databases': {'key': 'properties.databases', 'type': '[DatabaseBackupSetting]'},
        'backup_request_type': {'key': 'properties.type', 'type': 'BackupRestoreOperationType'},
    }

    def __init__(self, location, name=None, kind=None, type=None, tags=None, backup_request_name=None, enabled=None, storage_account_url=None, backup_schedule=None, databases=None, backup_request_type=None):
        super(BackupRequest, self).__init__(name=name, kind=kind, location=location, type=type, tags=tags)
        self.backup_request_name = backup_request_name
        self.enabled = enabled
        self.storage_account_url = storage_account_url
        self.backup_schedule = backup_schedule
        self.databases = databases
        self.backup_request_type = backup_request_type
