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

    :param id: Gets the id of the job.
    :type id: str
    :param sync_job_id: Gets the source control sync job id.
    :type sync_job_id: str
    :ivar creation_time: Gets the creation time of the job.
    :vartype creation_time: datetime
    :param provisioning_state: Gets the provisioning state of the job.
     Possible values include: 'Completed', 'Failed', 'Running'
    :type provisioning_state: str or
     ~azure.mgmt.automation.models.ProvisioningState
    :ivar start_time: Gets the start time of the job.
    :vartype start_time: datetime
    :ivar end_time: Gets the end time of the job.
    :vartype end_time: datetime
    :param start_type: Gets the type of start for the sync job. Possible
     values include: 'AutoSync', 'ManualSync'
    :type start_type: str or ~azure.mgmt.automation.models.StartType
    :param exception: Gets the exceptions that occured while running the sync
     job.
    :type exception: str
    """

    _validation = {
        'creation_time': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'sync_job_id': {'key': 'properties.syncJobId', 'type': 'str'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'start_type': {'key': 'properties.startType', 'type': 'str'},
        'exception': {'key': 'properties.exception', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SourceControlSyncJobById, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.sync_job_id = kwargs.get('sync_job_id', None)
        self.creation_time = None
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.start_time = None
        self.end_time = None
        self.start_type = kwargs.get('start_type', None)
        self.exception = kwargs.get('exception', None)
