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


class WorkflowRun(SubResource):
    """WorkflowRun

    :param id: Gets or sets the resource id.
    :type id: str
    :param start_time: Gets the start time.
    :type start_time: datetime
    :param end_time: Gets the end time.
    :type end_time: datetime
    :param status: Gets the status. Possible values include: 'NotSpecified',
     'Paused', 'Running', 'Waiting', 'Succeeded', 'Skipped', 'Suspended',
     'Cancelled', 'Failed', 'Faulted', 'TimedOut', 'Aborted'
    :type status: str
    :param code: Gets the code.
    :type code: str
    :param error: Gets the error.
    :type error: object
    :param correlation_id: Gets the correlation id.
    :type correlation_id: str
    :param workflow: Gets the reference to workflow version.
    :type workflow: :class:`ResourceReference
     <azure.mgmt.logic.models.ResourceReference>`
    :param trigger: Gets the fired trigger.
    :type trigger: :class:`WorkflowRunTrigger
     <azure.mgmt.logic.models.WorkflowRunTrigger>`
    :param outputs: Gets the outputs.
    :type outputs: dict
    :param name: Gets the workflow run name.
    :type name: str
    :param type: Gets the workflow run type.
    :type type: str
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'status': {'key': 'properties.status', 'type': 'WorkflowStatus'},
        'code': {'key': 'properties.code', 'type': 'str'},
        'error': {'key': 'properties.error', 'type': 'object'},
        'correlation_id': {'key': 'properties.correlationId', 'type': 'str'},
        'workflow': {'key': 'properties.workflow', 'type': 'ResourceReference'},
        'trigger': {'key': 'properties.trigger', 'type': 'WorkflowRunTrigger'},
        'outputs': {'key': 'properties.outputs', 'type': '{WorkflowOutputParameter}'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, id=None, start_time=None, end_time=None, status=None, code=None, error=None, correlation_id=None, workflow=None, trigger=None, outputs=None, name=None, type=None, **kwargs):
        super(WorkflowRun, self).__init__(id=id, **kwargs)
        self.start_time = start_time
        self.end_time = end_time
        self.status = status
        self.code = code
        self.error = error
        self.correlation_id = correlation_id
        self.workflow = workflow
        self.trigger = trigger
        self.outputs = outputs
        self.name = name
        self.type = type
