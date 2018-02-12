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


class ResourceStatistics(Model):
    """Statistics related to resource consumption by compute nodes in a pool.

    :param start_time: The start time of the time range covered by the
     statistics.
    :type start_time: datetime
    :param last_update_time: The time at which the statistics were last
     updated. All statistics are limited to the range between startTime and
     lastUpdateTime.
    :type last_update_time: datetime
    :param avg_cpu_percentage: The average CPU usage across all nodes in the
     pool (percentage per node).
    :type avg_cpu_percentage: float
    :param avg_memory_gi_b: The average memory usage in GiB across all nodes
     in the pool.
    :type avg_memory_gi_b: float
    :param peak_memory_gi_b: The peak memory usage in GiB across all nodes in
     the pool.
    :type peak_memory_gi_b: float
    :param avg_disk_gi_b: The average used disk space in GiB across all nodes
     in the pool.
    :type avg_disk_gi_b: float
    :param peak_disk_gi_b: The peak used disk space in GiB across all nodes in
     the pool.
    :type peak_disk_gi_b: float
    :param disk_read_iops: The total number of disk read operations across all
     nodes in the pool.
    :type disk_read_iops: long
    :param disk_write_iops: The total number of disk write operations across
     all nodes in the pool.
    :type disk_write_iops: long
    :param disk_read_gi_b: The total amount of data in GiB of disk reads
     across all nodes in the pool.
    :type disk_read_gi_b: float
    :param disk_write_gi_b: The total amount of data in GiB of disk writes
     across all nodes in the pool.
    :type disk_write_gi_b: float
    :param network_read_gi_b: The total amount of data in GiB of network reads
     across all nodes in the pool.
    :type network_read_gi_b: float
    :param network_write_gi_b: The total amount of data in GiB of network
     writes across all nodes in the pool.
    :type network_write_gi_b: float
    """

    _validation = {
        'start_time': {'required': True},
        'last_update_time': {'required': True},
        'avg_cpu_percentage': {'required': True},
        'avg_memory_gi_b': {'required': True},
        'peak_memory_gi_b': {'required': True},
        'avg_disk_gi_b': {'required': True},
        'peak_disk_gi_b': {'required': True},
        'disk_read_iops': {'required': True},
        'disk_write_iops': {'required': True},
        'disk_read_gi_b': {'required': True},
        'disk_write_gi_b': {'required': True},
        'network_read_gi_b': {'required': True},
        'network_write_gi_b': {'required': True},
    }

    _attribute_map = {
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'last_update_time': {'key': 'lastUpdateTime', 'type': 'iso-8601'},
        'avg_cpu_percentage': {'key': 'avgCPUPercentage', 'type': 'float'},
        'avg_memory_gi_b': {'key': 'avgMemoryGiB', 'type': 'float'},
        'peak_memory_gi_b': {'key': 'peakMemoryGiB', 'type': 'float'},
        'avg_disk_gi_b': {'key': 'avgDiskGiB', 'type': 'float'},
        'peak_disk_gi_b': {'key': 'peakDiskGiB', 'type': 'float'},
        'disk_read_iops': {'key': 'diskReadIOps', 'type': 'long'},
        'disk_write_iops': {'key': 'diskWriteIOps', 'type': 'long'},
        'disk_read_gi_b': {'key': 'diskReadGiB', 'type': 'float'},
        'disk_write_gi_b': {'key': 'diskWriteGiB', 'type': 'float'},
        'network_read_gi_b': {'key': 'networkReadGiB', 'type': 'float'},
        'network_write_gi_b': {'key': 'networkWriteGiB', 'type': 'float'},
    }

    def __init__(self, start_time, last_update_time, avg_cpu_percentage, avg_memory_gi_b, peak_memory_gi_b, avg_disk_gi_b, peak_disk_gi_b, disk_read_iops, disk_write_iops, disk_read_gi_b, disk_write_gi_b, network_read_gi_b, network_write_gi_b):
        super(ResourceStatistics, self).__init__()
        self.start_time = start_time
        self.last_update_time = last_update_time
        self.avg_cpu_percentage = avg_cpu_percentage
        self.avg_memory_gi_b = avg_memory_gi_b
        self.peak_memory_gi_b = peak_memory_gi_b
        self.avg_disk_gi_b = avg_disk_gi_b
        self.peak_disk_gi_b = peak_disk_gi_b
        self.disk_read_iops = disk_read_iops
        self.disk_write_iops = disk_write_iops
        self.disk_read_gi_b = disk_read_gi_b
        self.disk_write_gi_b = disk_write_gi_b
        self.network_read_gi_b = network_read_gi_b
        self.network_write_gi_b = network_write_gi_b
