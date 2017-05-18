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


class ApplicationHealthPolicyDefaultServiceTypeHealthPolicy(Model):
    """The policy of the default service type health.

    :param max_percent_unhealthy_services:
    :type max_percent_unhealthy_services: int
    :param max_percent_unhealthy_partitions_per_service:
    :type max_percent_unhealthy_partitions_per_service: int
    :param max_percent_unhealthy_replicas_per_partition:
    :type max_percent_unhealthy_replicas_per_partition: int
    """

    _attribute_map = {
        'max_percent_unhealthy_services': {'key': 'MaxPercentUnhealthyServices', 'type': 'int'},
        'max_percent_unhealthy_partitions_per_service': {'key': 'MaxPercentUnhealthyPartitionsPerService', 'type': 'int'},
        'max_percent_unhealthy_replicas_per_partition': {'key': 'MaxPercentUnhealthyReplicasPerPartition', 'type': 'int'},
    }

    def __init__(self, max_percent_unhealthy_services=None, max_percent_unhealthy_partitions_per_service=None, max_percent_unhealthy_replicas_per_partition=None):
        self.max_percent_unhealthy_services = max_percent_unhealthy_services
        self.max_percent_unhealthy_partitions_per_service = max_percent_unhealthy_partitions_per_service
        self.max_percent_unhealthy_replicas_per_partition = max_percent_unhealthy_replicas_per_partition
