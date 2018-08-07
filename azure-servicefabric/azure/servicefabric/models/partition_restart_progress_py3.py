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


class PartitionRestartProgress(Model):
    """Information about a partition restart user-induced operation.

    :param state: The state of the operation. Possible values include:
     'Invalid', 'Running', 'RollingBack', 'Completed', 'Faulted', 'Cancelled',
     'ForceCancelled'
    :type state: str or ~azure.servicefabric.models.OperationState
    :param restart_partition_result: Represents information about an operation
     in a terminal state (Completed or Faulted).
    :type restart_partition_result:
     ~azure.servicefabric.models.RestartPartitionResult
    """

    _attribute_map = {
        'state': {'key': 'State', 'type': 'str'},
        'restart_partition_result': {'key': 'RestartPartitionResult', 'type': 'RestartPartitionResult'},
    }

    def __init__(self, *, state=None, restart_partition_result=None, **kwargs) -> None:
        super(PartitionRestartProgress, self).__init__(**kwargs)
        self.state = state
        self.restart_partition_result = restart_partition_result
