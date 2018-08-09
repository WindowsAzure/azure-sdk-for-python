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

from .sub_resource import SubResource


class WorkflowRun(SubResource):
    """The workflow run.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The resource id.
    :vartype id: str
    :ivar start_time: Gets the start time.
    :vartype start_time: datetime
    :ivar end_time: Gets the end time.
    :vartype end_time: datetime
    :ivar status: Gets the status. Possible values include: 'NotSpecified',
     'Paused', 'Running', 'Waiting', 'Succeeded', 'Skipped', 'Suspended',
     'Cancelled', 'Failed', 'Faulted', 'TimedOut', 'Aborted', 'Ignored'
    :vartype status: str or ~azure.mgmt.logic.models.WorkflowStatus
    :ivar code: Gets the code.
    :vartype code: str
    :ivar error: Gets the error.
    :vartype error: object
    :ivar correlation_id: Gets the correlation id.
    :vartype correlation_id: str
    :param correlation: The run correlation.
    :type correlation: ~azure.mgmt.logic.models.Correlation
    :ivar workflow: Gets the reference to workflow version.
    :vartype workflow: ~azure.mgmt.logic.models.ResourceReference
    :ivar trigger: Gets the fired trigger.
    :vartype trigger: ~azure.mgmt.logic.models.WorkflowRunTrigger
    :ivar outputs: Gets the outputs.
    :vartype outputs: dict[str,
     ~azure.mgmt.logic.models.WorkflowOutputParameter]
    :ivar response: Gets the response of the flow run.
    :vartype response: ~azure.mgmt.logic.models.WorkflowRunTrigger
    :ivar name: Gets the workflow run name.
    :vartype name: str
    :ivar type: Gets the workflow run type.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
        'status': {'readonly': True},
        'code': {'readonly': True},
        'error': {'readonly': True},
        'correlation_id': {'readonly': True},
        'workflow': {'readonly': True},
        'trigger': {'readonly': True},
        'outputs': {'readonly': True},
        'response': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'start_time': {'key': 'properties.startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'properties.endTime', 'type': 'iso-8601'},
        'status': {'key': 'properties.status', 'type': 'WorkflowStatus'},
        'code': {'key': 'properties.code', 'type': 'str'},
        'error': {'key': 'properties.error', 'type': 'object'},
        'correlation_id': {'key': 'properties.correlationId', 'type': 'str'},
        'correlation': {'key': 'properties.correlation', 'type': 'Correlation'},
        'workflow': {'key': 'properties.workflow', 'type': 'ResourceReference'},
        'trigger': {'key': 'properties.trigger', 'type': 'WorkflowRunTrigger'},
        'outputs': {'key': 'properties.outputs', 'type': '{WorkflowOutputParameter}'},
        'response': {'key': 'properties.response', 'type': 'WorkflowRunTrigger'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(WorkflowRun, self).__init__(**kwargs)
        self.start_time = None
        self.end_time = None
        self.status = None
        self.code = None
        self.error = None
        self.correlation_id = None
        self.correlation = kwargs.get('correlation', None)
        self.workflow = None
        self.trigger = None
        self.outputs = None
        self.response = None
        self.name = None
        self.type = None
