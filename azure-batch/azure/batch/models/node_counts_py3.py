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


class NodeCounts(Model):
    """The number of nodes in each node state.

    All required parameters must be populated in order to send to Azure.

    :param creating: Required. The number of nodes in the creating state.
    :type creating: int
    :param idle: Required. The number of nodes in the idle state.
    :type idle: int
    :param offline: Required. The number of nodes in the offline state.
    :type offline: int
    :param preempted: Required. The number of nodes in the preempted state.
    :type preempted: int
    :param rebooting: Required. The count of nodes in the rebooting state.
    :type rebooting: int
    :param reimaging: Required. The number of nodes in the reimaging state.
    :type reimaging: int
    :param running: Required. The number of nodes in the running state.
    :type running: int
    :param starting: Required. The number of nodes in the starting state.
    :type starting: int
    :param start_task_failed: Required. The number of nodes in the
     startTaskFailed state.
    :type start_task_failed: int
    :param unknown: Required. The number of nodes in the unknown state.
    :type unknown: int
    :param unusable: Required. The number of nodes in the unusable state.
    :type unusable: int
    :param waiting_for_start_task: Required. The number of nodes in the
     waitingForStartTask state.
    :type waiting_for_start_task: int
    :param total: Required. The total number of nodes.
    :type total: int
    """

    _validation = {
        'creating': {'required': True},
        'idle': {'required': True},
        'offline': {'required': True},
        'preempted': {'required': True},
        'rebooting': {'required': True},
        'reimaging': {'required': True},
        'running': {'required': True},
        'starting': {'required': True},
        'start_task_failed': {'required': True},
        'unknown': {'required': True},
        'unusable': {'required': True},
        'waiting_for_start_task': {'required': True},
        'total': {'required': True},
    }

    _attribute_map = {
        'creating': {'key': 'creating', 'type': 'int'},
        'idle': {'key': 'idle', 'type': 'int'},
        'offline': {'key': 'offline', 'type': 'int'},
        'preempted': {'key': 'preempted', 'type': 'int'},
        'rebooting': {'key': 'rebooting', 'type': 'int'},
        'reimaging': {'key': 'reimaging', 'type': 'int'},
        'running': {'key': 'running', 'type': 'int'},
        'starting': {'key': 'starting', 'type': 'int'},
        'start_task_failed': {'key': 'startTaskFailed', 'type': 'int'},
        'unknown': {'key': 'unknown', 'type': 'int'},
        'unusable': {'key': 'unusable', 'type': 'int'},
        'waiting_for_start_task': {'key': 'waitingForStartTask', 'type': 'int'},
        'total': {'key': 'total', 'type': 'int'},
    }

    def __init__(self, *, creating: int, idle: int, offline: int, preempted: int, rebooting: int, reimaging: int, running: int, starting: int, start_task_failed: int, unknown: int, unusable: int, waiting_for_start_task: int, total: int, **kwargs) -> None:
        super(NodeCounts, self).__init__(**kwargs)
        self.creating = creating
        self.idle = idle
        self.offline = offline
        self.preempted = preempted
        self.rebooting = rebooting
        self.reimaging = reimaging
        self.running = running
        self.starting = starting
        self.start_task_failed = start_task_failed
        self.unknown = unknown
        self.unusable = unusable
        self.waiting_for_start_task = waiting_for_start_task
        self.total = total
