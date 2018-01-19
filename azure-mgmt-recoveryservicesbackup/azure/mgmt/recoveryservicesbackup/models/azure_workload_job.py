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

from .job import Job


class AzureWorkloadJob(Job):
    """Azure storage specific job.

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
    :param duration: Time elapsed during the execution of this job.
    :type duration: timedelta
    :param actions_info: Gets or sets the state/actions applicable on this job
     like cancel/retry.
    :type actions_info: list[str or
     ~azure.mgmt.recoveryservicesbackup.models.JobSupportedAction]
    :param error_details: Error details on execution of this job.
    :type error_details:
     list[~azure.mgmt.recoveryservicesbackup.models.AzureWorkloadErrorInfo]
    :param extended_info: Additional information about the job.
    :type extended_info:
     ~azure.mgmt.recoveryservicesbackup.models.AzureWorkloadJobExtendedInfo
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
        'duration': {'key': 'duration', 'type': 'duration'},
        'actions_info': {'key': 'actionsInfo', 'type': '[JobSupportedAction]'},
        'error_details': {'key': 'errorDetails', 'type': '[AzureWorkloadErrorInfo]'},
        'extended_info': {'key': 'extendedInfo', 'type': 'AzureWorkloadJobExtendedInfo'},
    }

    def __init__(self, entity_friendly_name=None, backup_management_type=None, operation=None, status=None, start_time=None, end_time=None, activity_id=None, duration=None, actions_info=None, error_details=None, extended_info=None):
        super(AzureWorkloadJob, self).__init__(entity_friendly_name=entity_friendly_name, backup_management_type=backup_management_type, operation=operation, status=status, start_time=start_time, end_time=end_time, activity_id=activity_id)
        self.duration = duration
        self.actions_info = actions_info
        self.error_details = error_details
        self.extended_info = extended_info
        self.job_type = 'AzureWorkloadJob'
