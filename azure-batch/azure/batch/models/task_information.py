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

from msrest.serialization import Model


class TaskInformation(Model):
    """
    Information about a task running on a compute node.

    :param task_url: The URL of the task.
    :type task_url: str
    :param job_id: The id of the job to which the task belongs.
    :type job_id: str
    :param task_id: The id of the task.
    :type task_id: str
    :param subtask_id: The id of the subtask if the task is a multi-instance
     task.
    :type subtask_id: int
    :param task_state: The current state of the task. Possible values
     include: 'active', 'preparing', 'running', 'completed'
    :type task_state: str or :class:`TaskState
     <batchserviceclient.models.TaskState>`
    :param execution_info: Information about the execution of the task.
    :type execution_info: :class:`TaskExecutionInformation
     <azure.batch.models.TaskExecutionInformation>`
    """ 

    _validation = {
        'task_state': {'required': True},
    }

    _attribute_map = {
        'task_url': {'key': 'taskUrl', 'type': 'str'},
        'job_id': {'key': 'jobId', 'type': 'str'},
        'task_id': {'key': 'taskId', 'type': 'str'},
        'subtask_id': {'key': 'subtaskId', 'type': 'int'},
        'task_state': {'key': 'taskState', 'type': 'TaskState'},
        'execution_info': {'key': 'executionInfo', 'type': 'TaskExecutionInformation'},
    }

    def __init__(self, task_state, task_url=None, job_id=None, task_id=None, subtask_id=None, execution_info=None):
        self.task_url = task_url
        self.job_id = job_id
        self.task_id = task_id
        self.subtask_id = subtask_id
        self.task_state = task_state
        self.execution_info = execution_info
