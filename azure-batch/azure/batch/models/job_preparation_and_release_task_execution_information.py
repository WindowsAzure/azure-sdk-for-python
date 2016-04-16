# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class JobPreparationAndReleaseTaskExecutionInformation(Model):
    """
    The status of the Job Preparation and Job Release tasks on a particular
    compute node.

    :param pool_id: Gets or sets the id of the pool containing the compute
     node to which this entry refers.
    :type pool_id: str
    :param node_id: Gets or sets the id of the compute node to which this
     entry refers.
    :type node_id: str
    :param node_url: Gets or sets the URL of the compute node to which this
     entry refers.
    :type node_url: str
    :param job_preparation_task_execution_info: Gets or sets information
     about the execution status of the Job Preparation task on this compute
     node.
    :type job_preparation_task_execution_info:
     :class:`JobPreparationTaskExecutionInformation
     <batchserviceclient.models.JobPreparationTaskExecutionInformation>`
    :param job_release_task_execution_info: Gets or sets information about
     the execution status of the Job Release task on this compute node. This
     property is set only if the Job Release task has run on the node.
    :type job_release_task_execution_info:
     :class:`JobReleaseTaskExecutionInformation
     <batchserviceclient.models.JobReleaseTaskExecutionInformation>`
    """ 

    _attribute_map = {
        'pool_id': {'key': 'poolId', 'type': 'str'},
        'node_id': {'key': 'nodeId', 'type': 'str'},
        'node_url': {'key': 'nodeUrl', 'type': 'str'},
        'job_preparation_task_execution_info': {'key': 'jobPreparationTaskExecutionInfo', 'type': 'JobPreparationTaskExecutionInformation'},
        'job_release_task_execution_info': {'key': 'jobReleaseTaskExecutionInfo', 'type': 'JobReleaseTaskExecutionInformation'},
    }

    def __init__(self, pool_id=None, node_id=None, node_url=None, job_preparation_task_execution_info=None, job_release_task_execution_info=None):
        self.pool_id = pool_id
        self.node_id = node_id
        self.node_url = node_url
        self.job_preparation_task_execution_info = job_preparation_task_execution_info
        self.job_release_task_execution_info = job_release_task_execution_info
