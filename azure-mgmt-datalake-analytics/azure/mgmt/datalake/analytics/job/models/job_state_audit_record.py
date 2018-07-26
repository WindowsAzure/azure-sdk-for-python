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


class JobStateAuditRecord(Model):
    """The Data Lake Analytics job state audit records for tracking the lifecycle
    of a job.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar new_state: The new state the job is in.
    :vartype new_state: str
    :ivar time_stamp: The time stamp that the state change took place.
    :vartype time_stamp: datetime
    :ivar requested_by_user: The user who requests the change.
    :vartype requested_by_user: str
    :ivar details: The details of the audit log.
    :vartype details: str
    """

    _validation = {
        'new_state': {'readonly': True},
        'time_stamp': {'readonly': True},
        'requested_by_user': {'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'new_state': {'key': 'newState', 'type': 'str'},
        'time_stamp': {'key': 'timeStamp', 'type': 'iso-8601'},
        'requested_by_user': {'key': 'requestedByUser', 'type': 'str'},
        'details': {'key': 'details', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(JobStateAuditRecord, self).__init__(**kwargs)
        self.new_state = None
        self.time_stamp = None
        self.requested_by_user = None
        self.details = None
