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


class Job(Model):
    """Defines workload agnostic properties for a job.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AzureIaaSVMJob, AzureStorageJob, AzureWorkloadJob, DpmJob,
    MabJob

    :param entity_friendly_name: Friendly name of the entity on which the
     current job is executing.
    :type entity_friendly_name: str
    :param backup_management_type: Backup management type to execute the
     current job. Possible values include: 'Invalid', 'AzureIaasVM', 'MAB',
     'DPM', 'AzureBackupServer', 'AzureSql', 'AzureStorage', 'AzureWorkload',
     'DefaultBackup'
    :type backup_management_type: str or
     ~azure.mgmt.recoveryservicesbackup.models.BackupManagementType
    :param operation: The operation name.
    :type operation: str
    :param status: Job status.
    :type status: str
    :param start_time: The start time.
    :type start_time: datetime
    :param end_time: The end time.
    :type end_time: datetime
    :param activity_id: ActivityId of job.
    :type activity_id: str
    :param job_type: Constant filled by server.
    :type job_type: str
    """

    _validation = {
        'job_type': {'required': True},
    }

    _attribute_map = {
        'entity_friendly_name': {'key': 'entityFriendlyName', 'type': 'str'},
        'backup_management_type': {'key': 'backupManagementType', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'activity_id': {'key': 'activityId', 'type': 'str'},
        'job_type': {'key': 'jobType', 'type': 'str'},
    }

    _subtype_map = {
        'job_type': {'AzureIaaSVMJob': 'AzureIaaSVMJob', 'AzureStorageJob': 'AzureStorageJob', 'AzureWorkloadJob': 'AzureWorkloadJob', 'DpmJob': 'DpmJob', 'MabJob': 'MabJob'}
    }

    def __init__(self, entity_friendly_name=None, backup_management_type=None, operation=None, status=None, start_time=None, end_time=None, activity_id=None):
        super(Job, self).__init__()
        self.entity_friendly_name = entity_friendly_name
        self.backup_management_type = backup_management_type
        self.operation = operation
        self.status = status
        self.start_time = start_time
        self.end_time = end_time
        self.activity_id = activity_id
        self.job_type = None
