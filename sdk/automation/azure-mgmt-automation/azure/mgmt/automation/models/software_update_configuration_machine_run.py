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


class SoftwareUpdateConfigurationMachineRun(Model):
    """Software update configuration machine run model.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Name of the software update configuration machine run
    :vartype name: str
    :ivar id: Resource Id of the software update configuration machine run
    :vartype id: str
    :ivar target_computer: name of the updated computer
    :vartype target_computer: str
    :ivar target_computer_type: type of the updated computer.
    :vartype target_computer_type: str
    :param software_update_configuration: software update configuration
     triggered this run
    :type software_update_configuration:
     ~azure.mgmt.automation.models.UpdateConfigurationNavigation
    :ivar status: Status of the software update configuration machine run.
    :vartype status: str
    :ivar os_type: Operating system target of the software update
     configuration triggered this run
    :vartype os_type: str
    :ivar correlation_id: correlation id of the software update configuration
     machine run
    :vartype correlation_id: str
    :ivar source_computer_id: source computer id of the software update
     configuration machine run
    :vartype source_computer_id: str
    :ivar start_time: Start time of the software update configuration machine
     run.
    :vartype start_time: datetime
    :ivar end_time: End time of the software update configuration machine run.
    :vartype end_time: datetime
    :ivar configured_duration: configured duration for the software update
     configuration run.
    :vartype configured_duration: str
    :param job: Job associated with the software update configuration machine
     run
    :type job: ~azure.mgmt.automation.models.JobNavigation
    :ivar creation_time: Creation time of the resource, which only appears in
     the response.
    :vartype creation_time: datetime
    :ivar created_by: createdBy property, which only appears in the response.
    :vartype created_by: str
    :ivar last_modified_time: Last time resource was modified, which only
     appears in the response.
    :vartype last_modified_time: datetime
    :ivar last_modified_by: lastModifiedBy property, which only appears in the
     response.
    :vartype last_modified_by: str
    :param error: Details of provisioning error
    :type error: ~azure.mgmt.automation.models.ErrorResponse
    """

    _validation = {
        'name': {'readonly': True},
        'id': {'readonly': True},
        'target_computer': {'readonly': True},
        'target_computer_type': {'readonly': True},
        'status': {'readonly': True},
        'os_type': {'readonly': True},
        'correlation_id': {'readonly': True},
        'source_computer_id': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
        'configured_duration': {'readonly': True},
        'creation_time': {'readonly': True},
        'created_by': {'readonly': True},
        'last_modified_time': {'readonly': True},
        'last_modified_by': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'target_computer': {'key': 'properties.targetComputer', 'type': 'str'},
        'target_computer_type': {'key': 'properties.targetComputerType', 'type': 'str'},
        'software_update_configuration': {'key': 'properties.softwareUpdateConfiguration', 'type': 'UpdateConfigurationNavigation'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'os_type': {'key': 'properties.osType', 'type': 'str'},
        'correlation_id': {'key': 'properties.correlationId', 'type': 'str'},
        'source_computer_id': {'key': 'properties.sourceComputerId', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'configured_duration': {'key': 'properties.configuredDuration', 'type': 'str'},
        'job': {'key': 'properties.job', 'type': 'JobNavigation'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'created_by': {'key': 'properties.createdBy', 'type': 'str'},
        'last_modified_time': {'key': 'properties.lastModifiedTime', 'type': 'iso-8601'},
        'last_modified_by': {'key': 'properties.lastModifiedBy', 'type': 'str'},
        'error': {'key': 'properties.error', 'type': 'ErrorResponse'},
    }

    def __init__(self, **kwargs):
        super(SoftwareUpdateConfigurationMachineRun, self).__init__(**kwargs)
        self.name = None
        self.id = None
        self.target_computer = None
        self.target_computer_type = None
        self.software_update_configuration = kwargs.get('software_update_configuration', None)
        self.status = None
        self.os_type = None
        self.correlation_id = None
        self.source_computer_id = None
        self.start_time = None
        self.end_time = None
        self.configured_duration = None
        self.job = kwargs.get('job', None)
        self.creation_time = None
        self.created_by = None
        self.last_modified_time = None
        self.last_modified_by = None
        self.error = kwargs.get('error', None)
