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


class CloudTask(Model):
    """
    An Azure Batch task.

    :param id: A string that uniquely identifies the task within the job. The
     id can contain any combination of alphanumeric characters including
     hyphens and underscores, and cannot contain more than 64 characters.
    :type id: str
    :param display_name: A display name for the task.
    :type display_name: str
    :param url: The URL of the task.
    :type url: str
    :param e_tag: The ETag of the task.
    :type e_tag: str
    :param last_modified: The last modified time of the task.
    :type last_modified: datetime
    :param creation_time: The creation time of the task.
    :type creation_time: datetime
    :param state: The current state of the task. Possible values include:
     'active', 'preparing', 'running', 'completed'
    :type state: str or :class:`TaskState <azure.batch.models.TaskState>`
    :param state_transition_time: The time at which the task entered its
     current state.
    :type state_transition_time: datetime
    :param previous_state: The previous state of the task. This property is
     not set if the task is in its initial Active state. Possible values
     include: 'active', 'preparing', 'running', 'completed'
    :type previous_state: str or :class:`TaskState
     <azure.batch.models.TaskState>`
    :param previous_state_transition_time: The time at which the task entered
     its previous state. This property is not set if the task is in its
     initial Active state.
    :type previous_state_transition_time: datetime
    :param command_line: The command line of the task. For multi-instance
     tasks, the command line is executed on the primary subtask after all the
     subtasks have finished executing the coordianation command line.
    :type command_line: str
    :param resource_files: A list of files that the Batch service will
     download to the compute node before running the command line. For
     multi-instance tasks, the resource files will only be downloaded to the
     compute node on which the primary subtask is executed.
    :type resource_files: list of :class:`ResourceFile
     <azure.batch.models.ResourceFile>`
    :param environment_settings: A list of environment variable settings for
     the task.
    :type environment_settings: list of :class:`EnvironmentSetting
     <azure.batch.models.EnvironmentSetting>`
    :param affinity_info: A locality hint that can be used by the Batch
     service to select a compute node on which to start the new task.
    :type affinity_info: :class:`AffinityInformation
     <azure.batch.models.AffinityInformation>`
    :param constraints: The execution constraints that apply to this task.
    :type constraints: :class:`TaskConstraints
     <azure.batch.models.TaskConstraints>`
    :param run_elevated: Whether to run the task in elevated mode.
    :type run_elevated: bool
    :param execution_info: Information about the execution of the task.
    :type execution_info: :class:`TaskExecutionInformation
     <azure.batch.models.TaskExecutionInformation>`
    :param node_info: Information about the compute node on which the task
     ran.
    :type node_info: :class:`ComputeNodeInformation
     <azure.batch.models.ComputeNodeInformation>`
    :param multi_instance_settings: Information about how to run the
     multi-instance task.
    :type multi_instance_settings: :class:`MultiInstanceSettings
     <azure.batch.models.MultiInstanceSettings>`
    :param stats: Resource usage statistics for the task.
    :type stats: :class:`TaskStatistics <azure.batch.models.TaskStatistics>`
    :param depends_on: Any dependencies this task has.
    :type depends_on: :class:`TaskDependencies
     <azure.batch.models.TaskDependencies>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'e_tag': {'key': 'eTag', 'type': 'str'},
        'last_modified': {'key': 'lastModified', 'type': 'iso-8601'},
        'creation_time': {'key': 'creationTime', 'type': 'iso-8601'},
        'state': {'key': 'state', 'type': 'TaskState'},
        'state_transition_time': {'key': 'stateTransitionTime', 'type': 'iso-8601'},
        'previous_state': {'key': 'previousState', 'type': 'TaskState'},
        'previous_state_transition_time': {'key': 'previousStateTransitionTime', 'type': 'iso-8601'},
        'command_line': {'key': 'commandLine', 'type': 'str'},
        'resource_files': {'key': 'resourceFiles', 'type': '[ResourceFile]'},
        'environment_settings': {'key': 'environmentSettings', 'type': '[EnvironmentSetting]'},
        'affinity_info': {'key': 'affinityInfo', 'type': 'AffinityInformation'},
        'constraints': {'key': 'constraints', 'type': 'TaskConstraints'},
        'run_elevated': {'key': 'runElevated', 'type': 'bool'},
        'execution_info': {'key': 'executionInfo', 'type': 'TaskExecutionInformation'},
        'node_info': {'key': 'nodeInfo', 'type': 'ComputeNodeInformation'},
        'multi_instance_settings': {'key': 'multiInstanceSettings', 'type': 'MultiInstanceSettings'},
        'stats': {'key': 'stats', 'type': 'TaskStatistics'},
        'depends_on': {'key': 'dependsOn', 'type': 'TaskDependencies'},
    }

    def __init__(self, id=None, display_name=None, url=None, e_tag=None, last_modified=None, creation_time=None, state=None, state_transition_time=None, previous_state=None, previous_state_transition_time=None, command_line=None, resource_files=None, environment_settings=None, affinity_info=None, constraints=None, run_elevated=None, execution_info=None, node_info=None, multi_instance_settings=None, stats=None, depends_on=None):
        self.id = id
        self.display_name = display_name
        self.url = url
        self.e_tag = e_tag
        self.last_modified = last_modified
        self.creation_time = creation_time
        self.state = state
        self.state_transition_time = state_transition_time
        self.previous_state = previous_state
        self.previous_state_transition_time = previous_state_transition_time
        self.command_line = command_line
        self.resource_files = resource_files
        self.environment_settings = environment_settings
        self.affinity_info = affinity_info
        self.constraints = constraints
        self.run_elevated = run_elevated
        self.execution_info = execution_info
        self.node_info = node_info
        self.multi_instance_settings = multi_instance_settings
        self.stats = stats
        self.depends_on = depends_on
