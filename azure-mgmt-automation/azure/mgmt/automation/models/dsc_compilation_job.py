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

from .proxy_resource import ProxyResource


class DscCompilationJob(ProxyResource):
    """Definition of the Dsc Compilation job.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param configuration: Gets or sets the configuration.
    :type configuration:
     ~azure.mgmt.automation.models.DscConfigurationAssociationProperty
    :ivar started_by: Gets the compilation job started by.
    :vartype started_by: str
    :ivar job_id: Gets the id of the job.
    :vartype job_id: str
    :ivar creation_time: Gets the creation time of the job.
    :vartype creation_time: datetime
    :ivar provisioning_state: The current provisioning state of the job.
    :vartype provisioning_state:
     ~azure.mgmt.automation.models.JobProvisioningStateProperty
    :param run_on: Gets or sets the runOn which specifies the group name where
     the job is to be executed.
    :type run_on: str
    :param status: Gets or sets the status of the job. Possible values
     include: 'New', 'Activating', 'Running', 'Completed', 'Failed', 'Stopped',
     'Blocked', 'Suspended', 'Disconnected', 'Suspending', 'Stopping',
     'Resuming', 'Removing'
    :type status: str or ~azure.mgmt.automation.models.JobStatus
    :param status_details: Gets or sets the status details of the job.
    :type status_details: str
    :ivar start_time: Gets the start time of the job.
    :vartype start_time: datetime
    :ivar end_time: Gets the end time of the job.
    :vartype end_time: datetime
    :ivar exception: Gets the exception of the job.
    :vartype exception: str
    :ivar last_modified_time: Gets the last modified time of the job.
    :vartype last_modified_time: datetime
    :ivar last_status_modified_time: Gets the last status modified time of the
     job.
    :vartype last_status_modified_time: datetime
    :param parameters: Gets or sets the parameters of the job.
    :type parameters: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'started_by': {'readonly': True},
        'job_id': {'readonly': True},
        'creation_time': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
        'exception': {'readonly': True},
        'last_modified_time': {'readonly': True},
        'last_status_modified_time': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'configuration': {'key': 'properties.configuration', 'type': 'DscConfigurationAssociationProperty'},
        'started_by': {'key': 'properties.startedBy', 'type': 'str'},
        'job_id': {'key': 'properties.jobId', 'type': 'str'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'JobProvisioningStateProperty'},
        'run_on': {'key': 'properties.runOn', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'status_details': {'key': 'properties.statusDetails', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'exception': {'key': 'properties.exception', 'type': 'str'},
        'last_modified_time': {'key': 'properties.lastModifiedTime', 'type': 'iso-8601'},
        'last_status_modified_time': {'key': 'properties.lastStatusModifiedTime', 'type': 'iso-8601'},
        'parameters': {'key': 'properties.parameters', 'type': '{str}'},
    }

    def __init__(self, configuration=None, run_on=None, status=None, status_details=None, parameters=None):
        super(DscCompilationJob, self).__init__()
        self.configuration = configuration
        self.started_by = None
        self.job_id = None
        self.creation_time = None
        self.provisioning_state = None
        self.run_on = run_on
        self.status = status
        self.status_details = status_details
        self.start_time = None
        self.end_time = None
        self.exception = None
        self.last_modified_time = None
        self.last_status_modified_time = None
        self.parameters = parameters
