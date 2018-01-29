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


class JobReleaseTaskExecutionInformation(Model):
    """Contains information about the execution of a Job Release task on a compute
    node.

    :param start_time: The time at which the task started running. If the task
     has been restarted or retried, this is the most recent time at which the
     task started running.
    :type start_time: datetime
    :param end_time: The time at which the Job Release task completed. This
     property is set only if the task is in the Completed state.
    :type end_time: datetime
    :param state: The current state of the Job Release task on the compute
     node. Possible values include: 'running', 'completed'
    :type state: str or ~azure.batch.models.JobReleaseTaskState
    :param task_root_directory: The root directory of the Job Release task on
     the compute node. You can use this path to retrieve files created by the
     task, such as log files.
    :type task_root_directory: str
    :param task_root_directory_url: The URL to the root directory of the Job
     Release task on the compute node.
    :type task_root_directory_url: str
    :param exit_code: The exit code of the program specified on the task
     command line. This parameter is returned only if the task is in the
     completed state. The exit code for a process reflects the specific
     convention implemented by the application developer for that process. If
     you use the exit code value to make decisions in your code, be sure that
     you know the exit code convention used by the application process. Note
     that the exit code may also be generated by the compute node operating
     system, such as when a process is forcibly terminated.
    :type exit_code: int
    :param container_info: Information about the container under which the
     task is executing. This property is set only if the task runs in a
     container context.
    :type container_info:
     ~azure.batch.models.TaskContainerExecutionInformation
    :param failure_info: Information describing the task failure, if any. This
     property is set only if the task is in the completed state and encountered
     a failure.
    :type failure_info: ~azure.batch.models.TaskFailureInformation
    :param result: The result of the task execution. If the value is 'failed',
     then the details of the failure can be found in the failureInfo property.
     Possible values include: 'success', 'failure'
    :type result: str or ~azure.batch.models.TaskExecutionResult
    """

    _validation = {
        'start_time': {'required': True},
        'state': {'required': True},
    }

    _attribute_map = {
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'state': {'key': 'state', 'type': 'JobReleaseTaskState'},
        'task_root_directory': {'key': 'taskRootDirectory', 'type': 'str'},
        'task_root_directory_url': {'key': 'taskRootDirectoryUrl', 'type': 'str'},
        'exit_code': {'key': 'exitCode', 'type': 'int'},
        'container_info': {'key': 'containerInfo', 'type': 'TaskContainerExecutionInformation'},
        'failure_info': {'key': 'failureInfo', 'type': 'TaskFailureInformation'},
        'result': {'key': 'result', 'type': 'TaskExecutionResult'},
    }

    def __init__(self, start_time, state, end_time=None, task_root_directory=None, task_root_directory_url=None, exit_code=None, container_info=None, failure_info=None, result=None):
        super(JobReleaseTaskExecutionInformation, self).__init__()
        self.start_time = start_time
        self.end_time = end_time
        self.state = state
        self.task_root_directory = task_root_directory
        self.task_root_directory_url = task_root_directory_url
        self.exit_code = exit_code
        self.container_info = container_info
        self.failure_info = failure_info
        self.result = result
