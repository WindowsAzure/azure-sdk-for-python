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


class JobStatisticsVertexStage(Model):
    """The Data Lake Analytics job statistics vertex stage information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar data_read: The amount of data read, in bytes.
    :vartype data_read: long
    :ivar data_read_cross_pod: The amount of data read across multiple pods,
     in bytes.
    :vartype data_read_cross_pod: long
    :ivar data_read_intra_pod: The amount of data read in one pod, in bytes.
    :vartype data_read_intra_pod: long
    :ivar data_to_read: The amount of data remaining to be read, in bytes.
    :vartype data_to_read: long
    :ivar data_written: The amount of data written, in bytes.
    :vartype data_written: long
    :ivar duplicate_discard_count: The number of duplicates that were
     discarded.
    :vartype duplicate_discard_count: int
    :ivar failed_count: The number of failures that occured in this stage.
    :vartype failed_count: int
    :ivar max_vertex_data_read: The maximum amount of data read in a single
     vertex, in bytes.
    :vartype max_vertex_data_read: long
    :ivar min_vertex_data_read: The minimum amount of data read in a single
     vertex, in bytes.
    :vartype min_vertex_data_read: long
    :ivar read_failure_count: The number of read failures in this stage.
    :vartype read_failure_count: int
    :ivar revocation_count: The number of vertices that were revoked during
     this stage.
    :vartype revocation_count: int
    :ivar running_count: The number of currently running vertices in this
     stage.
    :vartype running_count: int
    :ivar scheduled_count: The number of currently scheduled vertices in this
     stage.
    :vartype scheduled_count: int
    :ivar stage_name: The name of this stage in job execution.
    :vartype stage_name: str
    :ivar succeeded_count: The number of vertices that succeeded in this
     stage.
    :vartype succeeded_count: int
    :ivar temp_data_written: The amount of temporary data written, in bytes.
    :vartype temp_data_written: long
    :ivar total_count: The total vertex count for this stage.
    :vartype total_count: int
    :ivar total_failed_time: The amount of time that failed vertices took up
     in this stage.
    :vartype total_failed_time: timedelta
    :ivar total_progress: The current progress of this stage, as a percentage.
    :vartype total_progress: int
    :ivar total_succeeded_time: The amount of time all successful vertices
     took in this stage.
    :vartype total_succeeded_time: timedelta
    :ivar total_peak_mem_usage: The sum of the peak memory usage of all the
     vertices in the stage, in bytes.
    :vartype total_peak_mem_usage: long
    :ivar total_execution_time: The sum of the total execution time of all the
     vertices in the stage.
    :vartype total_execution_time: timedelta
    :param max_data_read_vertex: the vertex with the maximum amount of data
     read.
    :type max_data_read_vertex:
     ~azure.mgmt.datalake.analytics.job.models.JobStatisticsVertex
    :param max_execution_time_vertex: the vertex with the maximum execution
     time.
    :type max_execution_time_vertex:
     ~azure.mgmt.datalake.analytics.job.models.JobStatisticsVertex
    :param max_peak_mem_usage_vertex: the vertex with the maximum peak memory
     usage.
    :type max_peak_mem_usage_vertex:
     ~azure.mgmt.datalake.analytics.job.models.JobStatisticsVertex
    :ivar estimated_vertex_cpu_core_count: The estimated vertex CPU core
     count.
    :vartype estimated_vertex_cpu_core_count: int
    :ivar estimated_vertex_peak_cpu_core_count: The estimated vertex peak CPU
     core count.
    :vartype estimated_vertex_peak_cpu_core_count: int
    :ivar estimated_vertex_mem_size: The estimated vertex memory size, in
     bytes.
    :vartype estimated_vertex_mem_size: long
    :param allocated_container_cpu_core_count: The statistics information for
     the allocated container CPU core count.
    :type allocated_container_cpu_core_count:
     ~azure.mgmt.datalake.analytics.job.models.ResourceUsageStatistics
    :param allocated_container_mem_size: The statistics information for the
     allocated container memory size.
    :type allocated_container_mem_size:
     ~azure.mgmt.datalake.analytics.job.models.ResourceUsageStatistics
    :param used_vertex_cpu_core_count: The statistics information for the used
     vertex CPU core count.
    :type used_vertex_cpu_core_count:
     ~azure.mgmt.datalake.analytics.job.models.ResourceUsageStatistics
    :param used_vertex_peak_mem_size: The statistics information for the used
     vertex peak memory size.
    :type used_vertex_peak_mem_size:
     ~azure.mgmt.datalake.analytics.job.models.ResourceUsageStatistics
    """

    _validation = {
        'data_read': {'readonly': True},
        'data_read_cross_pod': {'readonly': True},
        'data_read_intra_pod': {'readonly': True},
        'data_to_read': {'readonly': True},
        'data_written': {'readonly': True},
        'duplicate_discard_count': {'readonly': True},
        'failed_count': {'readonly': True},
        'max_vertex_data_read': {'readonly': True},
        'min_vertex_data_read': {'readonly': True},
        'read_failure_count': {'readonly': True},
        'revocation_count': {'readonly': True},
        'running_count': {'readonly': True},
        'scheduled_count': {'readonly': True},
        'stage_name': {'readonly': True},
        'succeeded_count': {'readonly': True},
        'temp_data_written': {'readonly': True},
        'total_count': {'readonly': True},
        'total_failed_time': {'readonly': True},
        'total_progress': {'readonly': True},
        'total_succeeded_time': {'readonly': True},
        'total_peak_mem_usage': {'readonly': True},
        'total_execution_time': {'readonly': True},
        'estimated_vertex_cpu_core_count': {'readonly': True},
        'estimated_vertex_peak_cpu_core_count': {'readonly': True},
        'estimated_vertex_mem_size': {'readonly': True},
    }

    _attribute_map = {
        'data_read': {'key': 'dataRead', 'type': 'long'},
        'data_read_cross_pod': {'key': 'dataReadCrossPod', 'type': 'long'},
        'data_read_intra_pod': {'key': 'dataReadIntraPod', 'type': 'long'},
        'data_to_read': {'key': 'dataToRead', 'type': 'long'},
        'data_written': {'key': 'dataWritten', 'type': 'long'},
        'duplicate_discard_count': {'key': 'duplicateDiscardCount', 'type': 'int'},
        'failed_count': {'key': 'failedCount', 'type': 'int'},
        'max_vertex_data_read': {'key': 'maxVertexDataRead', 'type': 'long'},
        'min_vertex_data_read': {'key': 'minVertexDataRead', 'type': 'long'},
        'read_failure_count': {'key': 'readFailureCount', 'type': 'int'},
        'revocation_count': {'key': 'revocationCount', 'type': 'int'},
        'running_count': {'key': 'runningCount', 'type': 'int'},
        'scheduled_count': {'key': 'scheduledCount', 'type': 'int'},
        'stage_name': {'key': 'stageName', 'type': 'str'},
        'succeeded_count': {'key': 'succeededCount', 'type': 'int'},
        'temp_data_written': {'key': 'tempDataWritten', 'type': 'long'},
        'total_count': {'key': 'totalCount', 'type': 'int'},
        'total_failed_time': {'key': 'totalFailedTime', 'type': 'duration'},
        'total_progress': {'key': 'totalProgress', 'type': 'int'},
        'total_succeeded_time': {'key': 'totalSucceededTime', 'type': 'duration'},
        'total_peak_mem_usage': {'key': 'totalPeakMemUsage', 'type': 'long'},
        'total_execution_time': {'key': 'totalExecutionTime', 'type': 'duration'},
        'max_data_read_vertex': {'key': 'maxDataReadVertex', 'type': 'JobStatisticsVertex'},
        'max_execution_time_vertex': {'key': 'maxExecutionTimeVertex', 'type': 'JobStatisticsVertex'},
        'max_peak_mem_usage_vertex': {'key': 'maxPeakMemUsageVertex', 'type': 'JobStatisticsVertex'},
        'estimated_vertex_cpu_core_count': {'key': 'estimatedVertexCpuCoreCount', 'type': 'int'},
        'estimated_vertex_peak_cpu_core_count': {'key': 'estimatedVertexPeakCpuCoreCount', 'type': 'int'},
        'estimated_vertex_mem_size': {'key': 'estimatedVertexMemSize', 'type': 'long'},
        'allocated_container_cpu_core_count': {'key': 'allocatedContainerCpuCoreCount', 'type': 'ResourceUsageStatistics'},
        'allocated_container_mem_size': {'key': 'allocatedContainerMemSize', 'type': 'ResourceUsageStatistics'},
        'used_vertex_cpu_core_count': {'key': 'usedVertexCpuCoreCount', 'type': 'ResourceUsageStatistics'},
        'used_vertex_peak_mem_size': {'key': 'usedVertexPeakMemSize', 'type': 'ResourceUsageStatistics'},
    }

    def __init__(self, max_data_read_vertex=None, max_execution_time_vertex=None, max_peak_mem_usage_vertex=None, allocated_container_cpu_core_count=None, allocated_container_mem_size=None, used_vertex_cpu_core_count=None, used_vertex_peak_mem_size=None):
        super(JobStatisticsVertexStage, self).__init__()
        self.data_read = None
        self.data_read_cross_pod = None
        self.data_read_intra_pod = None
        self.data_to_read = None
        self.data_written = None
        self.duplicate_discard_count = None
        self.failed_count = None
        self.max_vertex_data_read = None
        self.min_vertex_data_read = None
        self.read_failure_count = None
        self.revocation_count = None
        self.running_count = None
        self.scheduled_count = None
        self.stage_name = None
        self.succeeded_count = None
        self.temp_data_written = None
        self.total_count = None
        self.total_failed_time = None
        self.total_progress = None
        self.total_succeeded_time = None
        self.total_peak_mem_usage = None
        self.total_execution_time = None
        self.max_data_read_vertex = max_data_read_vertex
        self.max_execution_time_vertex = max_execution_time_vertex
        self.max_peak_mem_usage_vertex = max_peak_mem_usage_vertex
        self.estimated_vertex_cpu_core_count = None
        self.estimated_vertex_peak_cpu_core_count = None
        self.estimated_vertex_mem_size = None
        self.allocated_container_cpu_core_count = allocated_container_cpu_core_count
        self.allocated_container_mem_size = allocated_container_mem_size
        self.used_vertex_cpu_core_count = used_vertex_cpu_core_count
        self.used_vertex_peak_mem_size = used_vertex_peak_mem_size
