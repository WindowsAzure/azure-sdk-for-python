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


class SourceControlSyncJobById(Model):
    """Definition of the source control sync job.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: The id of the job.
    :type id: str
    :param source_control_sync_job_id: The source control sync job id.
    :type source_control_sync_job_id: str
    :ivar creation_time: The creation time of the job.
    :vartype creation_time: datetime
    :param provisioning_state: The provisioning state of the job. Possible
     values include: 'Completed', 'Failed', 'Running'
    :type provisioning_state: str or
     ~azure.mgmt.automation.models.ProvisioningState
    :ivar start_time: The start time of the job.
    :vartype start_time: datetime
    :ivar end_time: The end time of the job.
    :vartype end_time: datetime
    :param sync_type: The sync type. Possible values include: 'PartialSync',
     'FullSync'
    :type sync_type: str or ~azure.mgmt.automation.models.SyncType
    :param exception: The exceptions that occurred while running the sync job.
    :type exception: str
    """

    _validation = {
        'creation_time': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'source_control_sync_job_id': {'key': 'properties.sourceControlSyncJobId', 'type': 'str'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'sync_type': {'key': 'properties.syncType', 'type': 'str'},
        'exception': {'key': 'properties.exception', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, source_control_sync_job_id: str=None, provisioning_state=None, sync_type=None, exception: str=None, **kwargs) -> None:
        super(SourceControlSyncJobById, self).__init__(**kwargs)
        self.id = id
        self.source_control_sync_job_id = source_control_sync_job_id
        self.creation_time = None
        self.provisioning_state = provisioning_state
        self.start_time = None
        self.end_time = None
        self.sync_type = sync_type
        self.exception = exception
