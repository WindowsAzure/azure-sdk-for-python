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


class ArmServiceTypeHealthPolicy(Model):
    """Represents the health policy used to evaluate the health of services
    belonging to a service type.
    .

    :param max_percent_unhealthy_services: The maximum percentage of services
     allowed to be unhealthy before your application is considered in error.
     . Default value: 0 .
    :type max_percent_unhealthy_services: int
    :param max_percent_unhealthy_partitions_per_service: The maximum
     percentage of partitions per service allowed to be unhealthy before your
     application is considered in error.
     . Default value: 0 .
    :type max_percent_unhealthy_partitions_per_service: int
    :param max_percent_unhealthy_replicas_per_partition: The maximum
     percentage of replicas per partition allowed to be unhealthy before your
     application is considered in error.
     . Default value: 0 .
    :type max_percent_unhealthy_replicas_per_partition: int
    """

    _validation = {
        'max_percent_unhealthy_services': {'maximum': 100, 'minimum': 0},
        'max_percent_unhealthy_partitions_per_service': {'maximum': 100, 'minimum': 0},
        'max_percent_unhealthy_replicas_per_partition': {'maximum': 100, 'minimum': 0},
    }

    _attribute_map = {
        'max_percent_unhealthy_services': {'key': 'maxPercentUnhealthyServices', 'type': 'int'},
        'max_percent_unhealthy_partitions_per_service': {'key': 'maxPercentUnhealthyPartitionsPerService', 'type': 'int'},
        'max_percent_unhealthy_replicas_per_partition': {'key': 'maxPercentUnhealthyReplicasPerPartition', 'type': 'int'},
    }

    def __init__(self, *, max_percent_unhealthy_services: int=0, max_percent_unhealthy_partitions_per_service: int=0, max_percent_unhealthy_replicas_per_partition: int=0, **kwargs) -> None:
        super(ArmServiceTypeHealthPolicy, self).__init__(**kwargs)
        self.max_percent_unhealthy_services = max_percent_unhealthy_services
        self.max_percent_unhealthy_partitions_per_service = max_percent_unhealthy_partitions_per_service
        self.max_percent_unhealthy_replicas_per_partition = max_percent_unhealthy_replicas_per_partition
