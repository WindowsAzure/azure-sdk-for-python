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


class TaskIdRange(Model):
    """A range of task IDs that a task can depend on. All tasks with IDs in the
    range must complete successfully before the dependent task can be
    scheduled.

    The start and end of the range are inclusive. For example, if a range has
    start 9 and end 12, then it represents tasks '9', '10', '11' and '12'.

    :param start: The first task ID in the range.
    :type start: int
    :param end: The last task ID in the range.
    :type end: int
    """

    _validation = {
        'start': {'required': True},
        'end': {'required': True},
    }

    _attribute_map = {
        'start': {'key': 'start', 'type': 'int'},
        'end': {'key': 'end', 'type': 'int'},
    }

    def __init__(self, start, end):
        super(TaskIdRange, self).__init__()
        self.start = start
        self.end = end
