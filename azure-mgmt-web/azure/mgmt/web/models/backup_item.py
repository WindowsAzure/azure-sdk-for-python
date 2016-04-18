# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class BackupItem(Resource):
    """
    Backup description

    :param id: Resource Id
    :type id: str
    :param name: Resource Name
    :type name: str
    :param kind: Kind of resource
    :type kind: str
    :param location: Resource Location
    :type location: str
    :param type: Resource type
    :type type: str
    :param tags: Resource tags
    :type tags: dict
    :param backup_item_id: Id of the backup.
    :type backup_item_id: int
    :param storage_account_url: SAS URL for the storage account container
     which contains this backup
    :type storage_account_url: str
    :param blob_name: Name of the blob which contains data for this backup
    :type blob_name: str
    :param backup_item_name: Name of this backup
    :type backup_item_name: str
    :param status: Backup status. Possible values include: 'InProgress',
     'Failed', 'Succeeded', 'TimedOut', 'Created', 'Skipped',
     'PartiallySucceeded', 'DeleteInProgress', 'DeleteFailed', 'Deleted'
    :type status: str
    :param size_in_bytes: Size of the backup in bytes
    :type size_in_bytes: long
    :param created: Timestamp of the backup creation
    :type created: datetime
    :param log: Details regarding this backup. Might contain an error message.
    :type log: str
    :param databases: List of databases included in the backup
    :type databases: list of :class:`DatabaseBackupSetting
     <azure.mgmt.web.models.DatabaseBackupSetting>`
    :param scheduled: True if this backup has been created due to a schedule
     being triggered.
    :type scheduled: bool
    :param last_restore_time_stamp: Timestamp of a last restore operation
     which used this backup.
    :type last_restore_time_stamp: datetime
    :param finished_time_stamp: Timestamp when this backup finished.
    :type finished_time_stamp: datetime
    :param correlation_id: Unique correlation identifier. Please use this
     along with the timestamp while communicating with Azure support.
    :type correlation_id: str
    :param website_size_in_bytes: Size of the original web app which has been
     backed up
    :type website_size_in_bytes: long
    """ 

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'backup_item_id': {'key': 'properties.id', 'type': 'int'},
        'storage_account_url': {'key': 'properties.storageAccountUrl', 'type': 'str'},
        'blob_name': {'key': 'properties.blobName', 'type': 'str'},
        'backup_item_name': {'key': 'properties.name', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'BackupItemStatus'},
        'size_in_bytes': {'key': 'properties.sizeInBytes', 'type': 'long'},
        'created': {'key': 'properties.created', 'type': 'iso-8601'},
        'log': {'key': 'properties.log', 'type': 'str'},
        'databases': {'key': 'properties.databases', 'type': '[DatabaseBackupSetting]'},
        'scheduled': {'key': 'properties.scheduled', 'type': 'bool'},
        'last_restore_time_stamp': {'key': 'properties.lastRestoreTimeStamp', 'type': 'iso-8601'},
        'finished_time_stamp': {'key': 'properties.finishedTimeStamp', 'type': 'iso-8601'},
        'correlation_id': {'key': 'properties.correlationId', 'type': 'str'},
        'website_size_in_bytes': {'key': 'properties.websiteSizeInBytes', 'type': 'long'},
    }

    def __init__(self, location, id=None, name=None, kind=None, type=None, tags=None, backup_item_id=None, storage_account_url=None, blob_name=None, backup_item_name=None, status=None, size_in_bytes=None, created=None, log=None, databases=None, scheduled=None, last_restore_time_stamp=None, finished_time_stamp=None, correlation_id=None, website_size_in_bytes=None):
        super(BackupItem, self).__init__(id=id, name=name, kind=kind, location=location, type=type, tags=tags)
        self.backup_item_id = backup_item_id
        self.storage_account_url = storage_account_url
        self.blob_name = blob_name
        self.backup_item_name = backup_item_name
        self.status = status
        self.size_in_bytes = size_in_bytes
        self.created = created
        self.log = log
        self.databases = databases
        self.scheduled = scheduled
        self.last_restore_time_stamp = last_restore_time_stamp
        self.finished_time_stamp = finished_time_stamp
        self.correlation_id = correlation_id
        self.website_size_in_bytes = website_size_in_bytes
