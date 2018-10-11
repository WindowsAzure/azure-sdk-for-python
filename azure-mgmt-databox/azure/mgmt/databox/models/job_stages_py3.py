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


class JobStages(Model):
    """Job stages.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar stage_name: Name of the job stage. Possible values include:
     'DeviceOrdered', 'DevicePrepared', 'Dispatched', 'Delivered', 'PickedUp',
     'AtAzureDC', 'DataCopy', 'Completed', 'CompletedWithErrors', 'Cancelled',
     'Failed_IssueReportedAtCustomer', 'Failed_IssueDetectedAtAzureDC',
     'Aborted'
    :vartype stage_name: str or ~azure.mgmt.databox.models.StageName
    :ivar display_name: Display name of the job stage.
    :vartype display_name: str
    :ivar stage_status: Status of the job stage. Possible values include:
     'None', 'InProgress', 'Succeeded', 'Failed', 'Cancelled', 'Cancelling',
     'SucceededWithErrors'
    :vartype stage_status: str or ~azure.mgmt.databox.models.StageStatus
    :ivar stage_time: Time for the job stage in UTC ISO 8601 format.
    :vartype stage_time: datetime
    :ivar job_stage_details: Job Stage Details
    :vartype job_stage_details: object
    :ivar error_details: Error details for the stage.
    :vartype error_details: list[~azure.mgmt.databox.models.JobErrorDetails]
    """

    _validation = {
        'stage_name': {'readonly': True},
        'display_name': {'readonly': True},
        'stage_status': {'readonly': True},
        'stage_time': {'readonly': True},
        'job_stage_details': {'readonly': True},
        'error_details': {'readonly': True},
    }

    _attribute_map = {
        'stage_name': {'key': 'stageName', 'type': 'StageName'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'stage_status': {'key': 'stageStatus', 'type': 'StageStatus'},
        'stage_time': {'key': 'stageTime', 'type': 'iso-8601'},
        'job_stage_details': {'key': 'jobStageDetails', 'type': 'object'},
        'error_details': {'key': 'errorDetails', 'type': '[JobErrorDetails]'},
    }

    def __init__(self, **kwargs) -> None:
        super(JobStages, self).__init__(**kwargs)
        self.stage_name = None
        self.display_name = None
        self.stage_status = None
        self.stage_time = None
        self.job_stage_details = None
        self.error_details = None
