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

from .task_step_update_parameters import TaskStepUpdateParameters


class FileTaskStepUpdateParameters(TaskStepUpdateParameters):
    """The properties of updating a task step.

    All required parameters must be populated in order to send to Azure.

    :param context_path: The URL(absolute or relative) of the source context
     for the task step.
    :type context_path: str
    :param context_access_token: The token (git PAT or SAS token of storage
     account blob) associated with the context for a step.
    :type context_access_token: str
    :param type: Required. Constant filled by server.
    :type type: str
    :param task_file_path: The task template/definition file path relative to
     the source context.
    :type task_file_path: str
    :param values_file_path: The values/parameters file path relative to the
     source context.
    :type values_file_path: str
    :param values: The collection of overridable values that can be passed
     when running a task.
    :type values:
     list[~azure.mgmt.containerregistry.v2019_05_01.models.SetValue]
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'context_path': {'key': 'contextPath', 'type': 'str'},
        'context_access_token': {'key': 'contextAccessToken', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'task_file_path': {'key': 'taskFilePath', 'type': 'str'},
        'values_file_path': {'key': 'valuesFilePath', 'type': 'str'},
        'values': {'key': 'values', 'type': '[SetValue]'},
    }

    def __init__(self, **kwargs):
        super(FileTaskStepUpdateParameters, self).__init__(**kwargs)
        self.task_file_path = kwargs.get('task_file_path', None)
        self.values_file_path = kwargs.get('values_file_path', None)
        self.values = kwargs.get('values', None)
        self.type = 'FileTask'
