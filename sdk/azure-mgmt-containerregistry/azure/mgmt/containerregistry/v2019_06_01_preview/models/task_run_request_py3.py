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

from .run_request_py3 import RunRequest


class TaskRunRequest(RunRequest):
    """The parameters for a task run request.

    All required parameters must be populated in order to send to Azure.

    :param is_archive_enabled: The value that indicates whether archiving is
     enabled for the run or not. Default value: False .
    :type is_archive_enabled: bool
    :param type: Required. Constant filled by server.
    :type type: str
    :param task_id: Required. The resource ID of task against which run has to
     be queued.
    :type task_id: str
    :param override_task_step_properties: Set of overridable parameters that
     can be passed when running a Task.
    :type override_task_step_properties:
     ~azure.mgmt.containerregistry.v2019_06_01_preview.models.OverrideTaskStepProperties
    """

    _validation = {
        'type': {'required': True},
        'task_id': {'required': True},
    }

    _attribute_map = {
        'is_archive_enabled': {'key': 'isArchiveEnabled', 'type': 'bool'},
        'type': {'key': 'type', 'type': 'str'},
        'task_id': {'key': 'taskId', 'type': 'str'},
        'override_task_step_properties': {'key': 'overrideTaskStepProperties', 'type': 'OverrideTaskStepProperties'},
    }

    def __init__(self, *, task_id: str, is_archive_enabled: bool=False, override_task_step_properties=None, **kwargs) -> None:
        super(TaskRunRequest, self).__init__(is_archive_enabled=is_archive_enabled, **kwargs)
        self.task_id = task_id
        self.override_task_step_properties = override_task_step_properties
        self.type = 'TaskRunRequest'
