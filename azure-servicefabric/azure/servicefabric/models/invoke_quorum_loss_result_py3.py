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


class InvokeQuorumLossResult(Model):
    """Represents information about an operation in a terminal state (Completed or
    Faulted).

    :param error_code: If OperationState is Completed, this is 0.  If
     OperationState is Faulted, this is an error code indicating the reason.
    :type error_code: int
    :param selected_partition: This class returns information about the
     partition that the user-induced operation acted upon.
    :type selected_partition: ~azure.servicefabric.models.SelectedPartition
    """

    _attribute_map = {
        'error_code': {'key': 'ErrorCode', 'type': 'int'},
        'selected_partition': {'key': 'SelectedPartition', 'type': 'SelectedPartition'},
    }

    def __init__(self, *, error_code: int=None, selected_partition=None, **kwargs) -> None:
        super(InvokeQuorumLossResult, self).__init__(**kwargs)
        self.error_code = error_code
        self.selected_partition = selected_partition
