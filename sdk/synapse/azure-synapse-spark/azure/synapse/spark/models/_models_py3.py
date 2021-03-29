# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import datetime
from typing import Dict, List, Optional, Union

import msrest.serialization

from ._spark_client_enums import *


class SparkBatchJob(msrest.serialization.Model):
    """SparkBatchJob.

    All required parameters must be populated in order to send to Azure.

    :param livy_info:
    :type livy_info: ~azure.synapse.spark.models.SparkBatchJobState
    :param name: The batch name.
    :type name: str
    :param workspace_name: The workspace name.
    :type workspace_name: str
    :param spark_pool_name: The Spark pool name.
    :type spark_pool_name: str
    :param submitter_name: The submitter name.
    :type submitter_name: str
    :param submitter_id: The submitter identifier.
    :type submitter_id: str
    :param artifact_id: The artifact identifier.
    :type artifact_id: str
    :param job_type: The job type. Possible values include: "SparkBatch", "SparkSession".
    :type job_type: str or ~azure.synapse.spark.models.SparkJobType
    :param result: The Spark batch job result. Possible values include: "Uncertain", "Succeeded",
     "Failed", "Cancelled".
    :type result: str or ~azure.synapse.spark.models.SparkBatchJobResultType
    :param scheduler: The scheduler information.
    :type scheduler: ~azure.synapse.spark.models.SparkScheduler
    :param plugin: The plugin information.
    :type plugin: ~azure.synapse.spark.models.SparkServicePlugin
    :param errors: The error information.
    :type errors: list[~azure.synapse.spark.models.SparkServiceError]
    :param tags: A set of tags. The tags.
    :type tags: dict[str, str]
    :param id: Required. The session Id.
    :type id: int
    :param app_id: The application id of this session.
    :type app_id: str
    :param app_info: The detailed application info.
    :type app_info: dict[str, str]
    :param state: The batch state.
    :type state: str
    :param log_lines: The log lines.
    :type log_lines: list[str]
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'livy_info': {'key': 'livyInfo', 'type': 'SparkBatchJobState'},
        'name': {'key': 'name', 'type': 'str'},
        'workspace_name': {'key': 'workspaceName', 'type': 'str'},
        'spark_pool_name': {'key': 'sparkPoolName', 'type': 'str'},
        'submitter_name': {'key': 'submitterName', 'type': 'str'},
        'submitter_id': {'key': 'submitterId', 'type': 'str'},
        'artifact_id': {'key': 'artifactId', 'type': 'str'},
        'job_type': {'key': 'jobType', 'type': 'str'},
        'result': {'key': 'result', 'type': 'str'},
        'scheduler': {'key': 'schedulerInfo', 'type': 'SparkScheduler'},
        'plugin': {'key': 'pluginInfo', 'type': 'SparkServicePlugin'},
        'errors': {'key': 'errorInfo', 'type': '[SparkServiceError]'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'id': {'key': 'id', 'type': 'int'},
        'app_id': {'key': 'appId', 'type': 'str'},
        'app_info': {'key': 'appInfo', 'type': '{str}'},
        'state': {'key': 'state', 'type': 'str'},
        'log_lines': {'key': 'log', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        id: int,
        livy_info: Optional["SparkBatchJobState"] = None,
        name: Optional[str] = None,
        workspace_name: Optional[str] = None,
        spark_pool_name: Optional[str] = None,
        submitter_name: Optional[str] = None,
        submitter_id: Optional[str] = None,
        artifact_id: Optional[str] = None,
        job_type: Optional[Union[str, "SparkJobType"]] = None,
        result: Optional[Union[str, "SparkBatchJobResultType"]] = None,
        scheduler: Optional["SparkScheduler"] = None,
        plugin: Optional["SparkServicePlugin"] = None,
        errors: Optional[List["SparkServiceError"]] = None,
        tags: Optional[Dict[str, str]] = None,
        app_id: Optional[str] = None,
        app_info: Optional[Dict[str, str]] = None,
        state: Optional[str] = None,
        log_lines: Optional[List[str]] = None,
        **kwargs
    ):
        super(SparkBatchJob, self).__init__(**kwargs)
        self.livy_info = livy_info
        self.name = name
        self.workspace_name = workspace_name
        self.spark_pool_name = spark_pool_name
        self.submitter_name = submitter_name
        self.submitter_id = submitter_id
        self.artifact_id = artifact_id
        self.job_type = job_type
        self.result = result
        self.scheduler = scheduler
        self.plugin = plugin
        self.errors = errors
        self.tags = tags
        self.id = id
        self.app_id = app_id
        self.app_info = app_info
        self.state = state
        self.log_lines = log_lines


class SparkBatchJobCollection(msrest.serialization.Model):
    """Response for batch list operation.

    All required parameters must be populated in order to send to Azure.

    :param from_property: Required. The start index of fetched sessions.
    :type from_property: int
    :param total: Required. Number of sessions fetched.
    :type total: int
    :param sessions: Batch list.
    :type sessions: list[~azure.synapse.spark.models.SparkBatchJob]
    """

    _validation = {
        'from_property': {'required': True},
        'total': {'required': True},
    }

    _attribute_map = {
        'from_property': {'key': 'from', 'type': 'int'},
        'total': {'key': 'total', 'type': 'int'},
        'sessions': {'key': 'sessions', 'type': '[SparkBatchJob]'},
    }

    def __init__(
        self,
        *,
        from_property: int,
        total: int,
        sessions: Optional[List["SparkBatchJob"]] = None,
        **kwargs
    ):
        super(SparkBatchJobCollection, self).__init__(**kwargs)
        self.from_property = from_property
        self.total = total
        self.sessions = sessions


class SparkBatchJobOptions(msrest.serialization.Model):
    """SparkBatchJobOptions.

    All required parameters must be populated in order to send to Azure.

    :param tags: A set of tags. Dictionary of :code:`<string>`.
    :type tags: dict[str, str]
    :param artifact_id:
    :type artifact_id: str
    :param name: Required.
    :type name: str
    :param file: Required.
    :type file: str
    :param class_name:
    :type class_name: str
    :param arguments:
    :type arguments: list[str]
    :param jars:
    :type jars: list[str]
    :param python_files:
    :type python_files: list[str]
    :param files:
    :type files: list[str]
    :param archives:
    :type archives: list[str]
    :param configuration: Dictionary of :code:`<string>`.
    :type configuration: dict[str, str]
    :param driver_memory:
    :type driver_memory: str
    :param driver_cores:
    :type driver_cores: int
    :param executor_memory:
    :type executor_memory: str
    :param executor_cores:
    :type executor_cores: int
    :param executor_count:
    :type executor_count: int
    """

    _validation = {
        'name': {'required': True},
        'file': {'required': True},
    }

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'artifact_id': {'key': 'artifactId', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'file': {'key': 'file', 'type': 'str'},
        'class_name': {'key': 'className', 'type': 'str'},
        'arguments': {'key': 'args', 'type': '[str]'},
        'jars': {'key': 'jars', 'type': '[str]'},
        'python_files': {'key': 'pyFiles', 'type': '[str]'},
        'files': {'key': 'files', 'type': '[str]'},
        'archives': {'key': 'archives', 'type': '[str]'},
        'configuration': {'key': 'conf', 'type': '{str}'},
        'driver_memory': {'key': 'driverMemory', 'type': 'str'},
        'driver_cores': {'key': 'driverCores', 'type': 'int'},
        'executor_memory': {'key': 'executorMemory', 'type': 'str'},
        'executor_cores': {'key': 'executorCores', 'type': 'int'},
        'executor_count': {'key': 'numExecutors', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        name: str,
        file: str,
        tags: Optional[Dict[str, str]] = None,
        artifact_id: Optional[str] = None,
        class_name: Optional[str] = None,
        arguments: Optional[List[str]] = None,
        jars: Optional[List[str]] = None,
        python_files: Optional[List[str]] = None,
        files: Optional[List[str]] = None,
        archives: Optional[List[str]] = None,
        configuration: Optional[Dict[str, str]] = None,
        driver_memory: Optional[str] = None,
        driver_cores: Optional[int] = None,
        executor_memory: Optional[str] = None,
        executor_cores: Optional[int] = None,
        executor_count: Optional[int] = None,
        **kwargs
    ):
        super(SparkBatchJobOptions, self).__init__(**kwargs)
        self.tags = tags
        self.artifact_id = artifact_id
        self.name = name
        self.file = file
        self.class_name = class_name
        self.arguments = arguments
        self.jars = jars
        self.python_files = python_files
        self.files = files
        self.archives = archives
        self.configuration = configuration
        self.driver_memory = driver_memory
        self.driver_cores = driver_cores
        self.executor_memory = executor_memory
        self.executor_cores = executor_cores
        self.executor_count = executor_count


class SparkBatchJobState(msrest.serialization.Model):
    """SparkBatchJobState.

    :param not_started_at: the time that at which "not_started" livy state was first seen.
    :type not_started_at: ~datetime.datetime
    :param starting_at: the time that at which "starting" livy state was first seen.
    :type starting_at: ~datetime.datetime
    :param running_at: the time that at which "running" livy state was first seen.
    :type running_at: ~datetime.datetime
    :param dead_at: time that at which "dead" livy state was first seen.
    :type dead_at: ~datetime.datetime
    :param success_at: the time that at which "success" livy state was first seen.
    :type success_at: ~datetime.datetime
    :param terminated_at: the time that at which "killed" livy state was first seen.
    :type terminated_at: ~datetime.datetime
    :param recovering_at: the time that at which "recovering" livy state was first seen.
    :type recovering_at: ~datetime.datetime
    :param current_state: the Spark job state.
    :type current_state: str
    :param job_creation_request:
    :type job_creation_request: ~azure.synapse.spark.models.SparkRequest
    """

    _attribute_map = {
        'not_started_at': {'key': 'notStartedAt', 'type': 'iso-8601'},
        'starting_at': {'key': 'startingAt', 'type': 'iso-8601'},
        'running_at': {'key': 'runningAt', 'type': 'iso-8601'},
        'dead_at': {'key': 'deadAt', 'type': 'iso-8601'},
        'success_at': {'key': 'successAt', 'type': 'iso-8601'},
        'terminated_at': {'key': 'killedAt', 'type': 'iso-8601'},
        'recovering_at': {'key': 'recoveringAt', 'type': 'iso-8601'},
        'current_state': {'key': 'currentState', 'type': 'str'},
        'job_creation_request': {'key': 'jobCreationRequest', 'type': 'SparkRequest'},
    }

    def __init__(
        self,
        *,
        not_started_at: Optional[datetime.datetime] = None,
        starting_at: Optional[datetime.datetime] = None,
        running_at: Optional[datetime.datetime] = None,
        dead_at: Optional[datetime.datetime] = None,
        success_at: Optional[datetime.datetime] = None,
        terminated_at: Optional[datetime.datetime] = None,
        recovering_at: Optional[datetime.datetime] = None,
        current_state: Optional[str] = None,
        job_creation_request: Optional["SparkRequest"] = None,
        **kwargs
    ):
        super(SparkBatchJobState, self).__init__(**kwargs)
        self.not_started_at = not_started_at
        self.starting_at = starting_at
        self.running_at = running_at
        self.dead_at = dead_at
        self.success_at = success_at
        self.terminated_at = terminated_at
        self.recovering_at = recovering_at
        self.current_state = current_state
        self.job_creation_request = job_creation_request


class SparkRequest(msrest.serialization.Model):
    """SparkRequest.

    :param name:
    :type name: str
    :param file:
    :type file: str
    :param class_name:
    :type class_name: str
    :param arguments:
    :type arguments: list[str]
    :param jars:
    :type jars: list[str]
    :param python_files:
    :type python_files: list[str]
    :param files:
    :type files: list[str]
    :param archives:
    :type archives: list[str]
    :param configuration: Dictionary of :code:`<string>`.
    :type configuration: dict[str, str]
    :param driver_memory:
    :type driver_memory: str
    :param driver_cores:
    :type driver_cores: int
    :param executor_memory:
    :type executor_memory: str
    :param executor_cores:
    :type executor_cores: int
    :param executor_count:
    :type executor_count: int
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'file': {'key': 'file', 'type': 'str'},
        'class_name': {'key': 'className', 'type': 'str'},
        'arguments': {'key': 'args', 'type': '[str]'},
        'jars': {'key': 'jars', 'type': '[str]'},
        'python_files': {'key': 'pyFiles', 'type': '[str]'},
        'files': {'key': 'files', 'type': '[str]'},
        'archives': {'key': 'archives', 'type': '[str]'},
        'configuration': {'key': 'conf', 'type': '{str}'},
        'driver_memory': {'key': 'driverMemory', 'type': 'str'},
        'driver_cores': {'key': 'driverCores', 'type': 'int'},
        'executor_memory': {'key': 'executorMemory', 'type': 'str'},
        'executor_cores': {'key': 'executorCores', 'type': 'int'},
        'executor_count': {'key': 'numExecutors', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        file: Optional[str] = None,
        class_name: Optional[str] = None,
        arguments: Optional[List[str]] = None,
        jars: Optional[List[str]] = None,
        python_files: Optional[List[str]] = None,
        files: Optional[List[str]] = None,
        archives: Optional[List[str]] = None,
        configuration: Optional[Dict[str, str]] = None,
        driver_memory: Optional[str] = None,
        driver_cores: Optional[int] = None,
        executor_memory: Optional[str] = None,
        executor_cores: Optional[int] = None,
        executor_count: Optional[int] = None,
        **kwargs
    ):
        super(SparkRequest, self).__init__(**kwargs)
        self.name = name
        self.file = file
        self.class_name = class_name
        self.arguments = arguments
        self.jars = jars
        self.python_files = python_files
        self.files = files
        self.archives = archives
        self.configuration = configuration
        self.driver_memory = driver_memory
        self.driver_cores = driver_cores
        self.executor_memory = executor_memory
        self.executor_cores = executor_cores
        self.executor_count = executor_count


class SparkScheduler(msrest.serialization.Model):
    """SparkScheduler.

    :param submitted_at:
    :type submitted_at: ~datetime.datetime
    :param scheduled_at:
    :type scheduled_at: ~datetime.datetime
    :param ended_at:
    :type ended_at: ~datetime.datetime
    :param cancellation_requested_at:
    :type cancellation_requested_at: ~datetime.datetime
    :param current_state:  Possible values include: "Queued", "Scheduled", "Ended".
    :type current_state: str or ~azure.synapse.spark.models.SchedulerCurrentState
    """

    _attribute_map = {
        'submitted_at': {'key': 'submittedAt', 'type': 'iso-8601'},
        'scheduled_at': {'key': 'scheduledAt', 'type': 'iso-8601'},
        'ended_at': {'key': 'endedAt', 'type': 'iso-8601'},
        'cancellation_requested_at': {'key': 'cancellationRequestedAt', 'type': 'iso-8601'},
        'current_state': {'key': 'currentState', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        submitted_at: Optional[datetime.datetime] = None,
        scheduled_at: Optional[datetime.datetime] = None,
        ended_at: Optional[datetime.datetime] = None,
        cancellation_requested_at: Optional[datetime.datetime] = None,
        current_state: Optional[Union[str, "SchedulerCurrentState"]] = None,
        **kwargs
    ):
        super(SparkScheduler, self).__init__(**kwargs)
        self.submitted_at = submitted_at
        self.scheduled_at = scheduled_at
        self.ended_at = ended_at
        self.cancellation_requested_at = cancellation_requested_at
        self.current_state = current_state


class SparkServiceError(msrest.serialization.Model):
    """SparkServiceError.

    :param message:
    :type message: str
    :param error_code:
    :type error_code: str
    :param source:  Possible values include: "System", "User", "Unknown", "Dependency".
    :type source: str or ~azure.synapse.spark.models.SparkErrorSource
    """

    _attribute_map = {
        'message': {'key': 'message', 'type': 'str'},
        'error_code': {'key': 'errorCode', 'type': 'str'},
        'source': {'key': 'source', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        message: Optional[str] = None,
        error_code: Optional[str] = None,
        source: Optional[Union[str, "SparkErrorSource"]] = None,
        **kwargs
    ):
        super(SparkServiceError, self).__init__(**kwargs)
        self.message = message
        self.error_code = error_code
        self.source = source


class SparkServicePlugin(msrest.serialization.Model):
    """SparkServicePlugin.

    :param preparation_started_at:
    :type preparation_started_at: ~datetime.datetime
    :param resource_acquisition_started_at:
    :type resource_acquisition_started_at: ~datetime.datetime
    :param submission_started_at:
    :type submission_started_at: ~datetime.datetime
    :param monitoring_started_at:
    :type monitoring_started_at: ~datetime.datetime
    :param cleanup_started_at:
    :type cleanup_started_at: ~datetime.datetime
    :param current_state:  Possible values include: "Preparation", "ResourceAcquisition", "Queued",
     "Submission", "Monitoring", "Cleanup", "Ended".
    :type current_state: str or ~azure.synapse.spark.models.PluginCurrentState
    """

    _attribute_map = {
        'preparation_started_at': {'key': 'preparationStartedAt', 'type': 'iso-8601'},
        'resource_acquisition_started_at': {'key': 'resourceAcquisitionStartedAt', 'type': 'iso-8601'},
        'submission_started_at': {'key': 'submissionStartedAt', 'type': 'iso-8601'},
        'monitoring_started_at': {'key': 'monitoringStartedAt', 'type': 'iso-8601'},
        'cleanup_started_at': {'key': 'cleanupStartedAt', 'type': 'iso-8601'},
        'current_state': {'key': 'currentState', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        preparation_started_at: Optional[datetime.datetime] = None,
        resource_acquisition_started_at: Optional[datetime.datetime] = None,
        submission_started_at: Optional[datetime.datetime] = None,
        monitoring_started_at: Optional[datetime.datetime] = None,
        cleanup_started_at: Optional[datetime.datetime] = None,
        current_state: Optional[Union[str, "PluginCurrentState"]] = None,
        **kwargs
    ):
        super(SparkServicePlugin, self).__init__(**kwargs)
        self.preparation_started_at = preparation_started_at
        self.resource_acquisition_started_at = resource_acquisition_started_at
        self.submission_started_at = submission_started_at
        self.monitoring_started_at = monitoring_started_at
        self.cleanup_started_at = cleanup_started_at
        self.current_state = current_state


class SparkSession(msrest.serialization.Model):
    """SparkSession.

    All required parameters must be populated in order to send to Azure.

    :param livy_info:
    :type livy_info: ~azure.synapse.spark.models.SparkSessionState
    :param name:
    :type name: str
    :param workspace_name:
    :type workspace_name: str
    :param spark_pool_name:
    :type spark_pool_name: str
    :param submitter_name:
    :type submitter_name: str
    :param submitter_id:
    :type submitter_id: str
    :param artifact_id:
    :type artifact_id: str
    :param job_type: The job type. Possible values include: "SparkBatch", "SparkSession".
    :type job_type: str or ~azure.synapse.spark.models.SparkJobType
    :param result:  Possible values include: "Uncertain", "Succeeded", "Failed", "Cancelled".
    :type result: str or ~azure.synapse.spark.models.SparkSessionResultType
    :param scheduler:
    :type scheduler: ~azure.synapse.spark.models.SparkScheduler
    :param plugin:
    :type plugin: ~azure.synapse.spark.models.SparkServicePlugin
    :param errors: The error information.
    :type errors: list[~azure.synapse.spark.models.SparkServiceError]
    :param tags: A set of tags. Dictionary of :code:`<string>`.
    :type tags: dict[str, str]
    :param id: Required.
    :type id: int
    :param app_id:
    :type app_id: str
    :param app_info: Dictionary of :code:`<string>`.
    :type app_info: dict[str, str]
    :param state:
    :type state: str
    :param log_lines:
    :type log_lines: list[str]
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'livy_info': {'key': 'livyInfo', 'type': 'SparkSessionState'},
        'name': {'key': 'name', 'type': 'str'},
        'workspace_name': {'key': 'workspaceName', 'type': 'str'},
        'spark_pool_name': {'key': 'sparkPoolName', 'type': 'str'},
        'submitter_name': {'key': 'submitterName', 'type': 'str'},
        'submitter_id': {'key': 'submitterId', 'type': 'str'},
        'artifact_id': {'key': 'artifactId', 'type': 'str'},
        'job_type': {'key': 'jobType', 'type': 'str'},
        'result': {'key': 'result', 'type': 'str'},
        'scheduler': {'key': 'schedulerInfo', 'type': 'SparkScheduler'},
        'plugin': {'key': 'pluginInfo', 'type': 'SparkServicePlugin'},
        'errors': {'key': 'errorInfo', 'type': '[SparkServiceError]'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'id': {'key': 'id', 'type': 'int'},
        'app_id': {'key': 'appId', 'type': 'str'},
        'app_info': {'key': 'appInfo', 'type': '{str}'},
        'state': {'key': 'state', 'type': 'str'},
        'log_lines': {'key': 'log', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        id: int,
        livy_info: Optional["SparkSessionState"] = None,
        name: Optional[str] = None,
        workspace_name: Optional[str] = None,
        spark_pool_name: Optional[str] = None,
        submitter_name: Optional[str] = None,
        submitter_id: Optional[str] = None,
        artifact_id: Optional[str] = None,
        job_type: Optional[Union[str, "SparkJobType"]] = None,
        result: Optional[Union[str, "SparkSessionResultType"]] = None,
        scheduler: Optional["SparkScheduler"] = None,
        plugin: Optional["SparkServicePlugin"] = None,
        errors: Optional[List["SparkServiceError"]] = None,
        tags: Optional[Dict[str, str]] = None,
        app_id: Optional[str] = None,
        app_info: Optional[Dict[str, str]] = None,
        state: Optional[str] = None,
        log_lines: Optional[List[str]] = None,
        **kwargs
    ):
        super(SparkSession, self).__init__(**kwargs)
        self.livy_info = livy_info
        self.name = name
        self.workspace_name = workspace_name
        self.spark_pool_name = spark_pool_name
        self.submitter_name = submitter_name
        self.submitter_id = submitter_id
        self.artifact_id = artifact_id
        self.job_type = job_type
        self.result = result
        self.scheduler = scheduler
        self.plugin = plugin
        self.errors = errors
        self.tags = tags
        self.id = id
        self.app_id = app_id
        self.app_info = app_info
        self.state = state
        self.log_lines = log_lines


class SparkSessionCollection(msrest.serialization.Model):
    """SparkSessionCollection.

    All required parameters must be populated in order to send to Azure.

    :param from_property: Required.
    :type from_property: int
    :param total: Required.
    :type total: int
    :param sessions:
    :type sessions: list[~azure.synapse.spark.models.SparkSession]
    """

    _validation = {
        'from_property': {'required': True},
        'total': {'required': True},
    }

    _attribute_map = {
        'from_property': {'key': 'from', 'type': 'int'},
        'total': {'key': 'total', 'type': 'int'},
        'sessions': {'key': 'sessions', 'type': '[SparkSession]'},
    }

    def __init__(
        self,
        *,
        from_property: int,
        total: int,
        sessions: Optional[List["SparkSession"]] = None,
        **kwargs
    ):
        super(SparkSessionCollection, self).__init__(**kwargs)
        self.from_property = from_property
        self.total = total
        self.sessions = sessions


class SparkSessionOptions(msrest.serialization.Model):
    """SparkSessionOptions.

    All required parameters must be populated in order to send to Azure.

    :param tags: A set of tags. Dictionary of :code:`<string>`.
    :type tags: dict[str, str]
    :param artifact_id:
    :type artifact_id: str
    :param name: Required.
    :type name: str
    :param file:
    :type file: str
    :param class_name:
    :type class_name: str
    :param arguments:
    :type arguments: list[str]
    :param jars:
    :type jars: list[str]
    :param python_files:
    :type python_files: list[str]
    :param files:
    :type files: list[str]
    :param archives:
    :type archives: list[str]
    :param configuration: Dictionary of :code:`<string>`.
    :type configuration: dict[str, str]
    :param driver_memory:
    :type driver_memory: str
    :param driver_cores:
    :type driver_cores: int
    :param executor_memory:
    :type executor_memory: str
    :param executor_cores:
    :type executor_cores: int
    :param executor_count:
    :type executor_count: int
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'artifact_id': {'key': 'artifactId', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'file': {'key': 'file', 'type': 'str'},
        'class_name': {'key': 'className', 'type': 'str'},
        'arguments': {'key': 'args', 'type': '[str]'},
        'jars': {'key': 'jars', 'type': '[str]'},
        'python_files': {'key': 'pyFiles', 'type': '[str]'},
        'files': {'key': 'files', 'type': '[str]'},
        'archives': {'key': 'archives', 'type': '[str]'},
        'configuration': {'key': 'conf', 'type': '{str}'},
        'driver_memory': {'key': 'driverMemory', 'type': 'str'},
        'driver_cores': {'key': 'driverCores', 'type': 'int'},
        'executor_memory': {'key': 'executorMemory', 'type': 'str'},
        'executor_cores': {'key': 'executorCores', 'type': 'int'},
        'executor_count': {'key': 'numExecutors', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        name: str,
        tags: Optional[Dict[str, str]] = None,
        artifact_id: Optional[str] = None,
        file: Optional[str] = None,
        class_name: Optional[str] = None,
        arguments: Optional[List[str]] = None,
        jars: Optional[List[str]] = None,
        python_files: Optional[List[str]] = None,
        files: Optional[List[str]] = None,
        archives: Optional[List[str]] = None,
        configuration: Optional[Dict[str, str]] = None,
        driver_memory: Optional[str] = None,
        driver_cores: Optional[int] = None,
        executor_memory: Optional[str] = None,
        executor_cores: Optional[int] = None,
        executor_count: Optional[int] = None,
        **kwargs
    ):
        super(SparkSessionOptions, self).__init__(**kwargs)
        self.tags = tags
        self.artifact_id = artifact_id
        self.name = name
        self.file = file
        self.class_name = class_name
        self.arguments = arguments
        self.jars = jars
        self.python_files = python_files
        self.files = files
        self.archives = archives
        self.configuration = configuration
        self.driver_memory = driver_memory
        self.driver_cores = driver_cores
        self.executor_memory = executor_memory
        self.executor_cores = executor_cores
        self.executor_count = executor_count


class SparkSessionState(msrest.serialization.Model):
    """SparkSessionState.

    :param not_started_at:
    :type not_started_at: ~datetime.datetime
    :param starting_at:
    :type starting_at: ~datetime.datetime
    :param idle_at:
    :type idle_at: ~datetime.datetime
    :param dead_at:
    :type dead_at: ~datetime.datetime
    :param shutting_down_at:
    :type shutting_down_at: ~datetime.datetime
    :param terminated_at: the time that at which "killed" livy state was first seen.
    :type terminated_at: ~datetime.datetime
    :param recovering_at:
    :type recovering_at: ~datetime.datetime
    :param busy_at:
    :type busy_at: ~datetime.datetime
    :param error_at:
    :type error_at: ~datetime.datetime
    :param current_state:
    :type current_state: str
    :param job_creation_request:
    :type job_creation_request: ~azure.synapse.spark.models.SparkRequest
    """

    _attribute_map = {
        'not_started_at': {'key': 'notStartedAt', 'type': 'iso-8601'},
        'starting_at': {'key': 'startingAt', 'type': 'iso-8601'},
        'idle_at': {'key': 'idleAt', 'type': 'iso-8601'},
        'dead_at': {'key': 'deadAt', 'type': 'iso-8601'},
        'shutting_down_at': {'key': 'shuttingDownAt', 'type': 'iso-8601'},
        'terminated_at': {'key': 'killedAt', 'type': 'iso-8601'},
        'recovering_at': {'key': 'recoveringAt', 'type': 'iso-8601'},
        'busy_at': {'key': 'busyAt', 'type': 'iso-8601'},
        'error_at': {'key': 'errorAt', 'type': 'iso-8601'},
        'current_state': {'key': 'currentState', 'type': 'str'},
        'job_creation_request': {'key': 'jobCreationRequest', 'type': 'SparkRequest'},
    }

    def __init__(
        self,
        *,
        not_started_at: Optional[datetime.datetime] = None,
        starting_at: Optional[datetime.datetime] = None,
        idle_at: Optional[datetime.datetime] = None,
        dead_at: Optional[datetime.datetime] = None,
        shutting_down_at: Optional[datetime.datetime] = None,
        terminated_at: Optional[datetime.datetime] = None,
        recovering_at: Optional[datetime.datetime] = None,
        busy_at: Optional[datetime.datetime] = None,
        error_at: Optional[datetime.datetime] = None,
        current_state: Optional[str] = None,
        job_creation_request: Optional["SparkRequest"] = None,
        **kwargs
    ):
        super(SparkSessionState, self).__init__(**kwargs)
        self.not_started_at = not_started_at
        self.starting_at = starting_at
        self.idle_at = idle_at
        self.dead_at = dead_at
        self.shutting_down_at = shutting_down_at
        self.terminated_at = terminated_at
        self.recovering_at = recovering_at
        self.busy_at = busy_at
        self.error_at = error_at
        self.current_state = current_state
        self.job_creation_request = job_creation_request


class SparkStatement(msrest.serialization.Model):
    """SparkStatement.

    All required parameters must be populated in order to send to Azure.

    :param id: Required.
    :type id: int
    :param code:
    :type code: str
    :param state:
    :type state: str
    :param output:
    :type output: ~azure.synapse.spark.models.SparkStatementOutput
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'int'},
        'code': {'key': 'code', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'output': {'key': 'output', 'type': 'SparkStatementOutput'},
    }

    def __init__(
        self,
        *,
        id: int,
        code: Optional[str] = None,
        state: Optional[str] = None,
        output: Optional["SparkStatementOutput"] = None,
        **kwargs
    ):
        super(SparkStatement, self).__init__(**kwargs)
        self.id = id
        self.code = code
        self.state = state
        self.output = output


class SparkStatementCancellationResult(msrest.serialization.Model):
    """SparkStatementCancellationResult.

    :param message: The msg property from the Livy API. The value is always "canceled".
    :type message: str
    """

    _attribute_map = {
        'message': {'key': 'msg', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        message: Optional[str] = None,
        **kwargs
    ):
        super(SparkStatementCancellationResult, self).__init__(**kwargs)
        self.message = message


class SparkStatementCollection(msrest.serialization.Model):
    """SparkStatementCollection.

    All required parameters must be populated in order to send to Azure.

    :param total: Required.
    :type total: int
    :param statements:
    :type statements: list[~azure.synapse.spark.models.SparkStatement]
    """

    _validation = {
        'total': {'required': True},
    }

    _attribute_map = {
        'total': {'key': 'total_statements', 'type': 'int'},
        'statements': {'key': 'statements', 'type': '[SparkStatement]'},
    }

    def __init__(
        self,
        *,
        total: int,
        statements: Optional[List["SparkStatement"]] = None,
        **kwargs
    ):
        super(SparkStatementCollection, self).__init__(**kwargs)
        self.total = total
        self.statements = statements


class SparkStatementOptions(msrest.serialization.Model):
    """SparkStatementOptions.

    :param code:
    :type code: str
    :param kind:  Possible values include: "spark", "pyspark", "dotnetspark", "sql".
    :type kind: str or ~azure.synapse.spark.models.SparkStatementLanguageType
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        kind: Optional[Union[str, "SparkStatementLanguageType"]] = None,
        **kwargs
    ):
        super(SparkStatementOptions, self).__init__(**kwargs)
        self.code = code
        self.kind = kind


class SparkStatementOutput(msrest.serialization.Model):
    """SparkStatementOutput.

    All required parameters must be populated in order to send to Azure.

    :param status:
    :type status: str
    :param execution_count: Required.
    :type execution_count: int
    :param data: Any object.
    :type data: object
    :param error_name:
    :type error_name: str
    :param error_value:
    :type error_value: str
    :param traceback:
    :type traceback: list[str]
    """

    _validation = {
        'execution_count': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'execution_count': {'key': 'execution_count', 'type': 'int'},
        'data': {'key': 'data', 'type': 'object'},
        'error_name': {'key': 'ename', 'type': 'str'},
        'error_value': {'key': 'evalue', 'type': 'str'},
        'traceback': {'key': 'traceback', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        execution_count: int,
        status: Optional[str] = None,
        data: Optional[object] = None,
        error_name: Optional[str] = None,
        error_value: Optional[str] = None,
        traceback: Optional[List[str]] = None,
        **kwargs
    ):
        super(SparkStatementOutput, self).__init__(**kwargs)
        self.status = status
        self.execution_count = execution_count
        self.data = data
        self.error_name = error_name
        self.error_value = error_value
        self.traceback = traceback
