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


class TaskDependencies(Model):
    """Specifies any dependencies of a task. Any task that is explicitly specified
    or within a dependency range must complete before the dependant task will
    be scheduled.

    :param task_ids: The list of task IDs that this task depends on. All tasks
     in this list must complete successfully before the dependent task can be
     scheduled.
    :type task_ids: list of str
    :param task_id_ranges: The list of task ID ranges that this task depends
     on. All tasks in all ranges must complete successfully before the
     dependent task can be scheduled.
    :type task_id_ranges: list of :class:`TaskIdRange
     <azure.batch.models.TaskIdRange>`
    """

    _attribute_map = {
        'task_ids': {'key': 'taskIds', 'type': '[str]'},
        'task_id_ranges': {'key': 'taskIdRanges', 'type': '[TaskIdRange]'},
    }

    def __init__(self, task_ids=None, task_id_ranges=None):
        self.task_ids = task_ids
        self.task_id_ranges = task_id_ranges
