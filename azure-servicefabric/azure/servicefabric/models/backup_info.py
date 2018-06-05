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


class BackupInfo(Model):
    """Represents a backup point which can be used to trigger a restore.

    :param backup_id: Unique backup ID .
    :type backup_id: str
    :param backup_chain_id: Unique backup chain ID. All backups part of the
     same chain has the same backup chain id. A backup chain is comprised of 1
     full backup and multiple incremental backups.
    :type backup_chain_id: str
    :param application_name: Name of the Service Fabric application this
     partition backup belongs to.
    :type application_name: str
    :param service_name: Name of the Service Fabric service this partition
     backup belongs to.
    :type service_name: str
    :param partition_information: Information about the partition to which
     this backup belongs to
    :type partition_information:
     ~azure.servicefabric.models.PartitionInformation
    :param backup_location: Location of the backup, relative to the backup
     store.
    :type backup_location: str
    :param backup_type: Describes the type of backup, whether its full or
     incremental. Possible values include: 'Invalid', 'Full', 'Incremental'
    :type backup_type: str or ~azure.servicefabric.models.BackupType
    :param epoch_of_last_backup_record: Epoch of the last record in this
     backup.
    :type epoch_of_last_backup_record: ~azure.servicefabric.models.BackupEpoch
    :param lsn_of_last_backup_record: LSN of the last record in this backup.
    :type lsn_of_last_backup_record: str
    :param creation_time_utc: The date time when this backup was taken.
    :type creation_time_utc: datetime
    :param failure_error: Denotes the failure encountered in getting backup
     point information.
    :type failure_error: ~azure.servicefabric.models.FabricErrorError
    """

    _attribute_map = {
        'backup_id': {'key': 'BackupId', 'type': 'str'},
        'backup_chain_id': {'key': 'BackupChainId', 'type': 'str'},
        'application_name': {'key': 'ApplicationName', 'type': 'str'},
        'service_name': {'key': 'ServiceName', 'type': 'str'},
        'partition_information': {'key': 'PartitionInformation', 'type': 'PartitionInformation'},
        'backup_location': {'key': 'BackupLocation', 'type': 'str'},
        'backup_type': {'key': 'BackupType', 'type': 'str'},
        'epoch_of_last_backup_record': {'key': 'EpochOfLastBackupRecord', 'type': 'BackupEpoch'},
        'lsn_of_last_backup_record': {'key': 'LsnOfLastBackupRecord', 'type': 'str'},
        'creation_time_utc': {'key': 'CreationTimeUtc', 'type': 'iso-8601'},
        'failure_error': {'key': 'FailureError', 'type': 'FabricErrorError'},
    }

    def __init__(self, **kwargs):
        super(BackupInfo, self).__init__(**kwargs)
        self.backup_id = kwargs.get('backup_id', None)
        self.backup_chain_id = kwargs.get('backup_chain_id', None)
        self.application_name = kwargs.get('application_name', None)
        self.service_name = kwargs.get('service_name', None)
        self.partition_information = kwargs.get('partition_information', None)
        self.backup_location = kwargs.get('backup_location', None)
        self.backup_type = kwargs.get('backup_type', None)
        self.epoch_of_last_backup_record = kwargs.get('epoch_of_last_backup_record', None)
        self.lsn_of_last_backup_record = kwargs.get('lsn_of_last_backup_record', None)
        self.creation_time_utc = kwargs.get('creation_time_utc', None)
        self.failure_error = kwargs.get('failure_error', None)
