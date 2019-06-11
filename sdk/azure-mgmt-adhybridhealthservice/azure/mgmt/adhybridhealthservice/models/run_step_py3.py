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


class RunStep(Model):
    """The run step for a run profile.

    :param batch_size: The batch size used by the run step.
    :type batch_size: int
    :param object_process_limit: The object processing limit.
    :type object_process_limit: int
    :param object_delete_limit: The object deletion limit.
    :type object_delete_limit: int
    :param page_size: The page size of the run step.
    :type page_size: int
    :param partition_id: The Id of the partition that a current run step
     operation is executing.
    :type partition_id: str
    :param operation_type: The run step operation types.
    :type operation_type: int
    :param timeout: The operation timeout.
    :type timeout: int
    """

    _attribute_map = {
        'batch_size': {'key': 'batchSize', 'type': 'int'},
        'object_process_limit': {'key': 'objectProcessLimit', 'type': 'int'},
        'object_delete_limit': {'key': 'objectDeleteLimit', 'type': 'int'},
        'page_size': {'key': 'pageSize', 'type': 'int'},
        'partition_id': {'key': 'partitionId', 'type': 'str'},
        'operation_type': {'key': 'operationType', 'type': 'int'},
        'timeout': {'key': 'timeout', 'type': 'int'},
    }

    def __init__(self, *, batch_size: int=None, object_process_limit: int=None, object_delete_limit: int=None, page_size: int=None, partition_id: str=None, operation_type: int=None, timeout: int=None, **kwargs) -> None:
        super(RunStep, self).__init__(**kwargs)
        self.batch_size = batch_size
        self.object_process_limit = object_process_limit
        self.object_delete_limit = object_delete_limit
        self.page_size = page_size
        self.partition_id = partition_id
        self.operation_type = operation_type
        self.timeout = timeout
