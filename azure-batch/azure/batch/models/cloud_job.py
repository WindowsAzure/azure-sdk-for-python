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


class CloudJob(Model):
    """An Azure Batch job.

    :param id: A string that uniquely identifies the job within the account.
     The id can contain any combination of alphanumeric characters including
     hyphens and underscores, and cannot contain more than 64 characters. It
     is common to use a GUID for the id.
    :type id: str
    :param display_name: The display name for the job.
    :type display_name: str
    :param uses_task_dependencies: The flag that determines if this job will
     use tasks with dependencies.
    :type uses_task_dependencies: bool
    :param url: The URL of the job.
    :type url: str
    :param e_tag: The ETag of the job.
    :type e_tag: str
    :param last_modified: The last modified time of the job.
    :type last_modified: datetime
    :param creation_time: The creation time of the job.
    :type creation_time: datetime
    :param state: The current state of the job. Possible values include:
     'active', 'disabling', 'disabled', 'enabling', 'terminating',
     'completed', 'deleting'
    :type state: str or :class:`JobState <azure.batch.models.JobState>`
    :param state_transition_time: The time at which the job entered its
     current state.
    :type state_transition_time: datetime
    :param previous_state: The previous state of the job. This property is
     not set if the job is in its initial Active state. Possible values
     include: 'active', 'disabling', 'disabled', 'enabling', 'terminating',
     'completed', 'deleting'
    :type previous_state: str or :class:`JobState
     <azure.batch.models.JobState>`
    :param previous_state_transition_time: The time at which the job entered
     its previous state. This property is not set if the job is in its
     initial Active state.
    :type previous_state_transition_time: datetime
    :param priority: The priority of the job. Priority values can range from
     -1000 to 1000, with -1000 being the lowest priority and 1000 being the
     highest priority. The default value is 0.
    :type priority: int
    :param constraints: The execution constraints for the job.
    :type constraints: :class:`JobConstraints
     <azure.batch.models.JobConstraints>`
    :param job_manager_task: Details of a Job Manager task to be launched
     when the job is started.
    :type job_manager_task: :class:`JobManagerTask
     <azure.batch.models.JobManagerTask>`
    :param job_preparation_task: The Job Preparation task.
    :type job_preparation_task: :class:`JobPreparationTask
     <azure.batch.models.JobPreparationTask>`
    :param job_release_task: The Job Release task.
    :type job_release_task: :class:`JobReleaseTask
     <azure.batch.models.JobReleaseTask>`
    :param common_environment_settings: The list of common environment
     variable settings. These environment variables are set for all tasks in
     the job (including the Job Manager, Job Preparation and Job Release
     tasks).
    :type common_environment_settings: list of :class:`EnvironmentSetting
     <azure.batch.models.EnvironmentSetting>`
    :param pool_info: The pool on which the Batch service runs the job's
     tasks.
    :type pool_info: :class:`PoolInformation
     <azure.batch.models.PoolInformation>`
    :param metadata: A list of name-value pairs associated with the job as
     metadata.
    :type metadata: list of :class:`MetadataItem
     <azure.batch.models.MetadataItem>`
    :param execution_info: The execution information for the job.
    :type execution_info: :class:`JobExecutionInformation
     <azure.batch.models.JobExecutionInformation>`
    :param stats: Resource usage statistics for the entire lifetime of the
     job.
    :type stats: :class:`JobStatistics <azure.batch.models.JobStatistics>`
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'uses_task_dependencies': {'key': 'usesTaskDependencies', 'type': 'bool'},
        'url': {'key': 'url', 'type': 'str'},
        'e_tag': {'key': 'eTag', 'type': 'str'},
        'last_modified': {'key': 'lastModified', 'type': 'iso-8601'},
        'creation_time': {'key': 'creationTime', 'type': 'iso-8601'},
        'state': {'key': 'state', 'type': 'JobState'},
        'state_transition_time': {'key': 'stateTransitionTime', 'type': 'iso-8601'},
        'previous_state': {'key': 'previousState', 'type': 'JobState'},
        'previous_state_transition_time': {'key': 'previousStateTransitionTime', 'type': 'iso-8601'},
        'priority': {'key': 'priority', 'type': 'int'},
        'constraints': {'key': 'constraints', 'type': 'JobConstraints'},
        'job_manager_task': {'key': 'jobManagerTask', 'type': 'JobManagerTask'},
        'job_preparation_task': {'key': 'jobPreparationTask', 'type': 'JobPreparationTask'},
        'job_release_task': {'key': 'jobReleaseTask', 'type': 'JobReleaseTask'},
        'common_environment_settings': {'key': 'commonEnvironmentSettings', 'type': '[EnvironmentSetting]'},
        'pool_info': {'key': 'poolInfo', 'type': 'PoolInformation'},
        'metadata': {'key': 'metadata', 'type': '[MetadataItem]'},
        'execution_info': {'key': 'executionInfo', 'type': 'JobExecutionInformation'},
        'stats': {'key': 'stats', 'type': 'JobStatistics'},
    }

    def __init__(self, id=None, display_name=None, uses_task_dependencies=None, url=None, e_tag=None, last_modified=None, creation_time=None, state=None, state_transition_time=None, previous_state=None, previous_state_transition_time=None, priority=None, constraints=None, job_manager_task=None, job_preparation_task=None, job_release_task=None, common_environment_settings=None, pool_info=None, metadata=None, execution_info=None, stats=None):
        self.id = id
        self.display_name = display_name
        self.uses_task_dependencies = uses_task_dependencies
        self.url = url
        self.e_tag = e_tag
        self.last_modified = last_modified
        self.creation_time = creation_time
        self.state = state
        self.state_transition_time = state_transition_time
        self.previous_state = previous_state
        self.previous_state_transition_time = previous_state_transition_time
        self.priority = priority
        self.constraints = constraints
        self.job_manager_task = job_manager_task
        self.job_preparation_task = job_preparation_task
        self.job_release_task = job_release_task
        self.common_environment_settings = common_environment_settings
        self.pool_info = pool_info
        self.metadata = metadata
        self.execution_info = execution_info
        self.stats = stats
