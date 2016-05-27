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


class ComputeNode(Model):
    """
    A compute node in the Batch service.

    :param id: The id of the compute node.
    :type id: str
    :param url: The URL of the compute node.
    :type url: str
    :param state: The current state of the compute node. Possible values
     include: 'idle', 'rebooting', 'reimaging', 'running', 'unusable',
     'creating', 'starting', 'waitingforstarttask', 'starttaskfailed',
     'unknown', 'leavingpool', 'offline'
    :type state: str or :class:`ComputeNodeState
     <batchserviceclient.models.ComputeNodeState>`
    :param scheduling_state: Whether the compute node should be available for
     task scheduling. Possible values include: 'enabled', 'disabled'
    :type scheduling_state: str or :class:`SchedulingState
     <batchserviceclient.models.SchedulingState>`
    :param state_transition_time: The time at which the compute node entered
     its current state.
    :type state_transition_time: datetime
    :param last_boot_time: The time at which the compute node was started.
    :type last_boot_time: datetime
    :param allocation_time: The time at which this compute node was allocated
     to the pool.
    :type allocation_time: datetime
    :param ip_address: The IP address that other compute nodes can use to
     communicate with this compute node.
    :type ip_address: str
    :param affinity_id: An identifier which can be passed in the Add Task API
     to request that the task be scheduled close to this compute node.
    :type affinity_id: str
    :param vm_size: The size of the virtual machine hosting the compute node.
    :type vm_size: str
    :param total_tasks_run: The total number of job tasks completed on the
     compute node. This includes Job Preparation, Job Release and Job Manager
     tasks, but not the pool start task.
    :type total_tasks_run: int
    :param running_tasks_count: The total number of currently running job
     tasks on the compute node. This includes Job Preparation, Job Release,
     and Job Manager tasks, but not the pool start task.
    :type running_tasks_count: int
    :param total_tasks_succeeded: The total number of job tasks which
     completed successfully (with exitCode 0) on the compute node. This
     includes Job Preparation, Job Release, and Job Manager tasks, but not
     the pool start task.
    :type total_tasks_succeeded: int
    :param recent_tasks: The list of tasks that are currently running on the
     compute node.
    :type recent_tasks: list of :class:`TaskInformation
     <azure.batch.models.TaskInformation>`
    :param start_task: The task specified to run on the compute node as it
     joins the pool.
    :type start_task: :class:`StartTask <azure.batch.models.StartTask>`
    :param start_task_info: Runtime information about the execution of the
     start task on the compute node.
    :type start_task_info: :class:`StartTaskInformation
     <azure.batch.models.StartTaskInformation>`
    :param certificate_references: The list of certificates installed on the
     compute node.
    :type certificate_references: list of :class:`CertificateReference
     <azure.batch.models.CertificateReference>`
    :param errors: The list of errors that are currently being encountered by
     the compute node.
    :type errors: list of :class:`ComputeNodeError
     <azure.batch.models.ComputeNodeError>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'state': {'key': 'state', 'type': 'ComputeNodeState'},
        'scheduling_state': {'key': 'schedulingState', 'type': 'SchedulingState'},
        'state_transition_time': {'key': 'stateTransitionTime', 'type': 'iso-8601'},
        'last_boot_time': {'key': 'lastBootTime', 'type': 'iso-8601'},
        'allocation_time': {'key': 'allocationTime', 'type': 'iso-8601'},
        'ip_address': {'key': 'ipAddress', 'type': 'str'},
        'affinity_id': {'key': 'affinityId', 'type': 'str'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'total_tasks_run': {'key': 'totalTasksRun', 'type': 'int'},
        'running_tasks_count': {'key': 'runningTasksCount', 'type': 'int'},
        'total_tasks_succeeded': {'key': 'totalTasksSucceeded', 'type': 'int'},
        'recent_tasks': {'key': 'recentTasks', 'type': '[TaskInformation]'},
        'start_task': {'key': 'startTask', 'type': 'StartTask'},
        'start_task_info': {'key': 'startTaskInfo', 'type': 'StartTaskInformation'},
        'certificate_references': {'key': 'certificateReferences', 'type': '[CertificateReference]'},
        'errors': {'key': 'errors', 'type': '[ComputeNodeError]'},
    }

    def __init__(self, id=None, url=None, state=None, scheduling_state=None, state_transition_time=None, last_boot_time=None, allocation_time=None, ip_address=None, affinity_id=None, vm_size=None, total_tasks_run=None, running_tasks_count=None, total_tasks_succeeded=None, recent_tasks=None, start_task=None, start_task_info=None, certificate_references=None, errors=None):
        self.id = id
        self.url = url
        self.state = state
        self.scheduling_state = scheduling_state
        self.state_transition_time = state_transition_time
        self.last_boot_time = last_boot_time
        self.allocation_time = allocation_time
        self.ip_address = ip_address
        self.affinity_id = affinity_id
        self.vm_size = vm_size
        self.total_tasks_run = total_tasks_run
        self.running_tasks_count = running_tasks_count
        self.total_tasks_succeeded = total_tasks_succeeded
        self.recent_tasks = recent_tasks
        self.start_task = start_task
        self.start_task_info = start_task_info
        self.certificate_references = certificate_references
        self.errors = errors
