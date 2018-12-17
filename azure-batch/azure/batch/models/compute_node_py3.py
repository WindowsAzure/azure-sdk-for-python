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


class ComputeNode(Model):
    """A compute node in the Batch service.

    :param id: The ID of the compute node. Every node that is added to a pool
     is assigned a unique ID. Whenever a node is removed from a pool, all of
     its local files are deleted, and the ID is reclaimed and could be reused
     for new nodes.
    :type id: str
    :param url: The URL of the compute node.
    :type url: str
    :param state: The current state of the compute node. The low-priority node
     has been preempted. Tasks which were running on the node when it was
     preempted will be rescheduled when another node becomes available.
     Possible values include: 'idle', 'rebooting', 'reimaging', 'running',
     'unusable', 'creating', 'starting', 'waitingForStartTask',
     'startTaskFailed', 'unknown', 'leavingPool', 'offline', 'preempted'
    :type state: str or ~azure.batch.models.ComputeNodeState
    :param scheduling_state: Whether the compute node is available for task
     scheduling. Possible values include: 'enabled', 'disabled'
    :type scheduling_state: str or ~azure.batch.models.SchedulingState
    :param state_transition_time: The time at which the compute node entered
     its current state.
    :type state_transition_time: datetime
    :param last_boot_time: The last time at which the compute node was
     started. This property may not be present if the node state is unusable.
    :type last_boot_time: datetime
    :param allocation_time: The time at which this compute node was allocated
     to the pool. This is the time when the node was initially allocated and
     doesn't change once set. It is not updated when the node is service healed
     or preempted.
    :type allocation_time: datetime
    :param ip_address: The IP address that other compute nodes can use to
     communicate with this compute node. Every node that is added to a pool is
     assigned a unique IP address. Whenever a node is removed from a pool, all
     of its local files are deleted, and the IP address is reclaimed and could
     be reused for new nodes.
    :type ip_address: str
    :param affinity_id: An identifier which can be passed when adding a task
     to request that the task be scheduled on this node. Note that this is just
     a soft affinity. If the target node is busy or unavailable at the time the
     task is scheduled, then the task will be scheduled elsewhere.
    :type affinity_id: str
    :param vm_size: The size of the virtual machine hosting the compute node.
     For information about available sizes of virtual machines in pools, see
     Choose a VM size for compute nodes in an Azure Batch pool
     (https://docs.microsoft.com/azure/batch/batch-pool-vm-sizes).
    :type vm_size: str
    :param total_tasks_run: The total number of job tasks completed on the
     compute node. This includes Job Manager tasks and normal tasks, but not
     Job Preparation, Job Release or Start tasks.
    :type total_tasks_run: int
    :param running_tasks_count: The total number of currently running job
     tasks on the compute node. This includes Job Manager tasks and normal
     tasks, but not Job Preparation, Job Release or Start tasks.
    :type running_tasks_count: int
    :param total_tasks_succeeded: The total number of job tasks which
     completed successfully (with exitCode 0) on the compute node. This
     includes Job Manager tasks and normal tasks, but not Job Preparation, Job
     Release or Start tasks.
    :type total_tasks_succeeded: int
    :param recent_tasks: A list of tasks whose state has recently changed.
     This property is present only if at least one task has run on this node
     since it was assigned to the pool.
    :type recent_tasks: list[~azure.batch.models.TaskInformation]
    :param start_task: The task specified to run on the compute node as it
     joins the pool.
    :type start_task: ~azure.batch.models.StartTask
    :param start_task_info: Runtime information about the execution of the
     start task on the compute node.
    :type start_task_info: ~azure.batch.models.StartTaskInformation
    :param certificate_references: The list of certificates installed on the
     compute node. For Windows compute nodes, the Batch service installs the
     certificates to the specified certificate store and location. For Linux
     compute nodes, the certificates are stored in a directory inside the task
     working directory and an environment variable AZ_BATCH_CERTIFICATES_DIR is
     supplied to the task to query for this location. For certificates with
     visibility of 'remoteUser', a 'certs' directory is created in the user's
     home directory (e.g., /home/{user-name}/certs) and certificates are placed
     in that directory.
    :type certificate_references:
     list[~azure.batch.models.CertificateReference]
    :param errors: The list of errors that are currently being encountered by
     the compute node.
    :type errors: list[~azure.batch.models.ComputeNodeError]
    :param is_dedicated: Whether this compute node is a dedicated node. If
     false, the node is a low-priority node.
    :type is_dedicated: bool
    :param endpoint_configuration: The endpoint configuration for the compute
     node.
    :type endpoint_configuration:
     ~azure.batch.models.ComputeNodeEndpointConfiguration
    :param node_agent_info: Information about the node agent version and the
     time the node upgraded to a new version.
    :type node_agent_info: ~azure.batch.models.NodeAgentInformation
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
        'is_dedicated': {'key': 'isDedicated', 'type': 'bool'},
        'endpoint_configuration': {'key': 'endpointConfiguration', 'type': 'ComputeNodeEndpointConfiguration'},
        'node_agent_info': {'key': 'nodeAgentInfo', 'type': 'NodeAgentInformation'},
    }

    def __init__(self, *, id: str=None, url: str=None, state=None, scheduling_state=None, state_transition_time=None, last_boot_time=None, allocation_time=None, ip_address: str=None, affinity_id: str=None, vm_size: str=None, total_tasks_run: int=None, running_tasks_count: int=None, total_tasks_succeeded: int=None, recent_tasks=None, start_task=None, start_task_info=None, certificate_references=None, errors=None, is_dedicated: bool=None, endpoint_configuration=None, node_agent_info=None, **kwargs) -> None:
        super(ComputeNode, self).__init__(**kwargs)
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
        self.is_dedicated = is_dedicated
        self.endpoint_configuration = endpoint_configuration
        self.node_agent_info = node_agent_info
