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


class JobRecurrenceInformation(Model):
    """Recurrence job information for a specific recurrence.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar recurrence_id: the recurrence identifier (a GUID), unique per
     activity/script, regardless of iterations. This is something to link
     different occurrences of the same job together.
    :vartype recurrence_id: str
    :ivar recurrence_name: the recurrence name, user friendly name for the
     correlation between jobs.
    :vartype recurrence_name: str
    :ivar num_jobs_failed: the number of jobs in this recurrence that have
     failed.
    :vartype num_jobs_failed: int
    :ivar num_jobs_canceled: the number of jobs in this recurrence that have
     been canceled.
    :vartype num_jobs_canceled: int
    :ivar num_jobs_succeeded: the number of jobs in this recurrence that have
     succeeded.
    :vartype num_jobs_succeeded: int
    :ivar au_hours_failed: the number of job execution hours that resulted in
     failed jobs.
    :vartype au_hours_failed: float
    :ivar au_hours_canceled: the number of job execution hours that resulted
     in canceled jobs.
    :vartype au_hours_canceled: float
    :ivar au_hours_succeeded: the number of job execution hours that resulted
     in successful jobs.
    :vartype au_hours_succeeded: float
    :ivar last_submit_time: the last time a job in this recurrence was
     submitted.
    :vartype last_submit_time: datetime
    """

    _validation = {
        'recurrence_id': {'readonly': True},
        'recurrence_name': {'readonly': True},
        'num_jobs_failed': {'readonly': True},
        'num_jobs_canceled': {'readonly': True},
        'num_jobs_succeeded': {'readonly': True},
        'au_hours_failed': {'readonly': True},
        'au_hours_canceled': {'readonly': True},
        'au_hours_succeeded': {'readonly': True},
        'last_submit_time': {'readonly': True},
    }

    _attribute_map = {
        'recurrence_id': {'key': 'recurrenceId', 'type': 'str'},
        'recurrence_name': {'key': 'recurrenceName', 'type': 'str'},
        'num_jobs_failed': {'key': 'numJobsFailed', 'type': 'int'},
        'num_jobs_canceled': {'key': 'numJobsCanceled', 'type': 'int'},
        'num_jobs_succeeded': {'key': 'numJobsSucceeded', 'type': 'int'},
        'au_hours_failed': {'key': 'auHoursFailed', 'type': 'float'},
        'au_hours_canceled': {'key': 'auHoursCanceled', 'type': 'float'},
        'au_hours_succeeded': {'key': 'auHoursSucceeded', 'type': 'float'},
        'last_submit_time': {'key': 'lastSubmitTime', 'type': 'iso-8601'},
    }

    def __init__(self):
        super(JobRecurrenceInformation, self).__init__()
        self.recurrence_id = None
        self.recurrence_name = None
        self.num_jobs_failed = None
        self.num_jobs_canceled = None
        self.num_jobs_succeeded = None
        self.au_hours_failed = None
        self.au_hours_canceled = None
        self.au_hours_succeeded = None
        self.last_submit_time = None
