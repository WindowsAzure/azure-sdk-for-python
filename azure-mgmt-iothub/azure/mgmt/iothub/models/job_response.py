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


class JobResponse(Model):
    """The properties of the Job Response object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar job_id: The job identifier.
    :vartype job_id: str
    :ivar start_time_utc: The start time of the Job.
    :vartype start_time_utc: datetime
    :ivar end_time_utc: The time the job stopped processing.
    :vartype end_time_utc: datetime
    :ivar type: The type of the job. Possible values include: 'unknown',
     'export', 'import', 'backup', 'readDeviceProperties',
     'writeDeviceProperties', 'updateDeviceConfiguration', 'rebootDevice',
     'factoryResetDevice', 'firmwareUpdate'
    :vartype type: str or :class:`JobType <azure.mgmt.iothub.models.JobType>`
    :ivar status: The status of the job. Possible values include: 'unknown',
     'enqueued', 'running', 'completed', 'failed', 'cancelled'
    :vartype status: str or :class:`JobStatus
     <azure.mgmt.iothub.models.JobStatus>`
    :ivar failure_reason: If status == failed, this string containing the
     reason for the failure.
    :vartype failure_reason: str
    :ivar status_message: The status message for the job.
    :vartype status_message: str
    :ivar parent_job_id: The job identifier of the parent job, if any.
    :vartype parent_job_id: str
    """

    _validation = {
        'job_id': {'readonly': True},
        'start_time_utc': {'readonly': True},
        'end_time_utc': {'readonly': True},
        'type': {'readonly': True},
        'status': {'readonly': True},
        'failure_reason': {'readonly': True},
        'status_message': {'readonly': True},
        'parent_job_id': {'readonly': True},
    }

    _attribute_map = {
        'job_id': {'key': 'jobId', 'type': 'str'},
        'start_time_utc': {'key': 'startTimeUtc', 'type': 'rfc-1123'},
        'end_time_utc': {'key': 'endTimeUtc', 'type': 'rfc-1123'},
        'type': {'key': 'type', 'type': 'str'},
        'status': {'key': 'status', 'type': 'JobStatus'},
        'failure_reason': {'key': 'failureReason', 'type': 'str'},
        'status_message': {'key': 'statusMessage', 'type': 'str'},
        'parent_job_id': {'key': 'parentJobId', 'type': 'str'},
    }

    def __init__(self):
        self.job_id = None
        self.start_time_utc = None
        self.end_time_utc = None
        self.type = None
        self.status = None
        self.failure_reason = None
        self.status_message = None
        self.parent_job_id = None
