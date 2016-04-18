# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .sub_resource import SubResource


class WorkflowTrigger(SubResource):
    """WorkflowTrigger

    :param id: Gets or sets the resource id.
    :type id: str
    :param provisioning_state: Gets the provisioning state. Possible values
     include: 'NotSpecified', 'Creating', 'Succeeded', 'Updating'
    :type provisioning_state: str
    :param created_time: Gets the created time.
    :type created_time: datetime
    :param changed_time: Gets the changed time.
    :type changed_time: datetime
    :param state: Gets the state. Possible values include: 'NotSpecified',
     'Enabled', 'Disabled', 'Deleted', 'Suspended'
    :type state: str
    :param status: Gets the status. Possible values include: 'NotSpecified',
     'Paused', 'Running', 'Waiting', 'Succeeded', 'Skipped', 'Suspended',
     'Cancelled', 'Failed', 'Faulted', 'TimedOut', 'Aborted'
    :type status: str
    :param last_execution_time: Gets the last execution time.
    :type last_execution_time: datetime
    :param next_execution_time: Gets the next execution time.
    :type next_execution_time: datetime
    :param recurrence: Gets the workflow trigger recurrence.
    :type recurrence: :class:`WorkflowTriggerRecurrence
     <logicmanagementclient.models.WorkflowTriggerRecurrence>`
    :param workflow: Gets the reference to workflow.
    :type workflow: :class:`ResourceReference
     <logicmanagementclient.models.ResourceReference>`
    :param name: Gets the workflow trigger name.
    :type name: str
    :param type: Gets the workflow trigger type.
    :type type: str
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'WorkflowTriggerProvisioningState'},
        'created_time': {'key': 'properties.createdTime', 'type': 'iso-8601'},
        'changed_time': {'key': 'properties.changedTime', 'type': 'iso-8601'},
        'state': {'key': 'properties.state', 'type': 'WorkflowState'},
        'status': {'key': 'properties.status', 'type': 'WorkflowStatus'},
        'last_execution_time': {'key': 'properties.lastExecutionTime', 'type': 'iso-8601'},
        'next_execution_time': {'key': 'properties.nextExecutionTime', 'type': 'iso-8601'},
        'recurrence': {'key': 'properties.recurrence', 'type': 'WorkflowTriggerRecurrence'},
        'workflow': {'key': 'properties.workflow', 'type': 'ResourceReference'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, id=None, provisioning_state=None, created_time=None, changed_time=None, state=None, status=None, last_execution_time=None, next_execution_time=None, recurrence=None, workflow=None, name=None, type=None):
        super(WorkflowTrigger, self).__init__(id=id)
        self.provisioning_state = provisioning_state
        self.created_time = created_time
        self.changed_time = changed_time
        self.state = state
        self.status = status
        self.last_execution_time = last_execution_time
        self.next_execution_time = next_execution_time
        self.recurrence = recurrence
        self.workflow = workflow
        self.name = name
        self.type = type
