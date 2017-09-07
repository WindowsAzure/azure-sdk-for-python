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


class SiteLimits(Model):
    """Metric limits set on an app.

    :param max_percentage_cpu: Maximum allowed CPU usage percentage.
    :type max_percentage_cpu: float
    :param max_memory_in_mb: Maximum allowed memory usage in MB.
    :type max_memory_in_mb: long
    :param max_disk_size_in_mb: Maximum allowed disk size usage in MB.
    :type max_disk_size_in_mb: long
    """

    _attribute_map = {
        'max_percentage_cpu': {'key': 'maxPercentageCpu', 'type': 'float'},
        'max_memory_in_mb': {'key': 'maxMemoryInMb', 'type': 'long'},
        'max_disk_size_in_mb': {'key': 'maxDiskSizeInMb', 'type': 'long'},
    }

    def __init__(self, max_percentage_cpu=None, max_memory_in_mb=None, max_disk_size_in_mb=None):
        self.max_percentage_cpu = max_percentage_cpu
        self.max_memory_in_mb = max_memory_in_mb
        self.max_disk_size_in_mb = max_disk_size_in_mb
