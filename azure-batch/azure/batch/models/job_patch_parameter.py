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


class JobPatchParameter(Model):
    """Parameters for a CloudJobOperations.Patch request.

    :param priority: The priority of the job. Priority values can range from
     -1000 to 1000, with -1000 being the lowest priority and 1000 being the
     highest priority. If omitted, the priority of the job is left unchanged.
    :type priority: int
    :param constraints: The execution constraints for the job. If omitted,
     the existing execution constraints are left unchanged.
    :type constraints: :class:`JobConstraints
     <azure.batch.models.JobConstraints>`
    :param pool_info: The pool on which the Batch service runs the job's
     tasks. If omitted, the job continues to run on its current pool.
    :type pool_info: :class:`PoolInformation
     <azure.batch.models.PoolInformation>`
    :param metadata: A list of name-value pairs associated with the job as
     metadata. If omitted, the existing job metadata is left unchanged.
    :type metadata: list of :class:`MetadataItem
     <azure.batch.models.MetadataItem>`
    """ 

    _attribute_map = {
        'priority': {'key': 'priority', 'type': 'int'},
        'constraints': {'key': 'constraints', 'type': 'JobConstraints'},
        'pool_info': {'key': 'poolInfo', 'type': 'PoolInformation'},
        'metadata': {'key': 'metadata', 'type': '[MetadataItem]'},
    }

    def __init__(self, priority=None, constraints=None, pool_info=None, metadata=None):
        self.priority = priority
        self.constraints = constraints
        self.pool_info = pool_info
        self.metadata = metadata
