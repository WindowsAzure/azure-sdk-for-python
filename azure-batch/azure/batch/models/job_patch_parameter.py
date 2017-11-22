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
    """The set of changes to be made to a job.

    :param priority: The priority of the job. Priority values can range from
     -1000 to 1000, with -1000 being the lowest priority and 1000 being the
     highest priority. If omitted, the priority of the job is left unchanged.
    :type priority: int
    :param on_all_tasks_complete: The action the Batch service should take
     when all tasks in the job are in the completed state. If omitted, the
     completion behavior is left unchanged. You may not change the value from
     terminatejob to noaction - that is, once you have engaged automatic job
     termination, you cannot turn it off again. If you try to do this, the
     request fails with an 'invalid property value' error response; if you are
     calling the REST API directly, the HTTP status code is 400 (Bad Request).
     Possible values include: 'noAction', 'terminateJob'
    :type on_all_tasks_complete: str or ~azure.batch.models.OnAllTasksComplete
    :param constraints: The execution constraints for the job. If omitted, the
     existing execution constraints are left unchanged.
    :type constraints: ~azure.batch.models.JobConstraints
    :param pool_info: The pool on which the Batch service runs the job's
     tasks. You may change the pool for a job only when the job is disabled.
     The Patch Job call will fail if you include the poolInfo element and the
     job is not disabled. If you specify an autoPoolSpecification specification
     in the poolInfo, only the keepAlive property can be updated, and then only
     if the auto pool has a poolLifetimeOption of job. If omitted, the job
     continues to run on its current pool.
    :type pool_info: ~azure.batch.models.PoolInformation
    :param metadata: A list of name-value pairs associated with the job as
     metadata. If omitted, the existing job metadata is left unchanged.
    :type metadata: list[~azure.batch.models.MetadataItem]
    """

    _attribute_map = {
        'priority': {'key': 'priority', 'type': 'int'},
        'on_all_tasks_complete': {'key': 'onAllTasksComplete', 'type': 'OnAllTasksComplete'},
        'constraints': {'key': 'constraints', 'type': 'JobConstraints'},
        'pool_info': {'key': 'poolInfo', 'type': 'PoolInformation'},
        'metadata': {'key': 'metadata', 'type': '[MetadataItem]'},
    }

    def __init__(self, priority=None, on_all_tasks_complete=None, constraints=None, pool_info=None, metadata=None):
        self.priority = priority
        self.on_all_tasks_complete = on_all_tasks_complete
        self.constraints = constraints
        self.pool_info = pool_info
        self.metadata = metadata
