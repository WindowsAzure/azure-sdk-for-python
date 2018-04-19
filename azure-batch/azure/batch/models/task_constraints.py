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


class TaskConstraints(Model):
    """Execution constraints to apply to a task.

    :param max_wall_clock_time: The maximum elapsed time that the task may
     run, measured from the time the task starts. If the task does not complete
     within the time limit, the Batch service terminates it. If this is not
     specified, there is no time limit on how long the task may run.
    :type max_wall_clock_time: timedelta
    :param retention_time: The minimum time to retain the task directory on
     the compute node where it ran, from the time it completes execution. After
     this time, the Batch service may delete the task directory and all its
     contents. The default is infinite, i.e. the task directory will be
     retained until the compute node is removed or reimaged.
    :type retention_time: timedelta
    :param max_task_retry_count: The maximum number of times the task may be
     retried. The Batch service retries a task if its exit code is nonzero.
     Note that this value specifically controls the number of retries for the
     task executable due to a nonzero exit code. The Batch service will try the
     task once, and may then retry up to this limit. For example, if the
     maximum retry count is 3, Batch tries the task up to 4 times (one initial
     try and 3 retries). If the maximum retry count is 0, the Batch service
     does not retry the task after the first attempt. If the maximum retry
     count is -1, the Batch service retries the task without limit. Resource
     files and application packages are only downloaded again if the task is
     retried on a new compute node.
    :type max_task_retry_count: int
    """

    _attribute_map = {
        'max_wall_clock_time': {'key': 'maxWallClockTime', 'type': 'duration'},
        'retention_time': {'key': 'retentionTime', 'type': 'duration'},
        'max_task_retry_count': {'key': 'maxTaskRetryCount', 'type': 'int'},
    }

    def __init__(self, max_wall_clock_time=None, retention_time=None, max_task_retry_count=None):
        super(TaskConstraints, self).__init__()
        self.max_wall_clock_time = max_wall_clock_time
        self.retention_time = retention_time
        self.max_task_retry_count = max_task_retry_count
