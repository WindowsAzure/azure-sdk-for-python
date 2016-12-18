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


class PoolInformation(Model):
    """Specifies how a job should be assigned to a pool.

    :param pool_id: The ID of an existing pool. All the tasks of the job will
     run on the specified pool. You must ensure that the pool referenced by
     this property exists. If the pool does not exist at the time the Batch
     service tries to schedule a job, no tasks for the job will run until you
     create a pool with that id. Note that the Batch service will not reject
     the job request; it will simply not run tasks until the pool exists. You
     must specify either the pool ID or the auto pool specification, but not
     both.
    :type pool_id: str
    :param auto_pool_specification: Characteristics for a temporary 'auto
     pool'. The Batch service will create this auto pool when the job is
     submitted. If auto pool creation fails, the Batch service moves the job to
     a completed state, and the pool creation error is set in the job's
     scheduling error property. The Batch service manages the lifetime (both
     creation and, unless keepAlive is specified, deletion) of the auto pool.
     Any user actions that affect the lifetime of the auto pool while the job
     is active will result in unexpected behavior. You must specify either the
     pool ID or the auto pool specification, but not both.
    :type auto_pool_specification: :class:`AutoPoolSpecification
     <azure.batch.models.AutoPoolSpecification>`
    """

    _attribute_map = {
        'pool_id': {'key': 'poolId', 'type': 'str'},
        'auto_pool_specification': {'key': 'autoPoolSpecification', 'type': 'AutoPoolSpecification'},
    }

    def __init__(self, pool_id=None, auto_pool_specification=None):
        self.pool_id = pool_id
        self.auto_pool_specification = auto_pool_specification
