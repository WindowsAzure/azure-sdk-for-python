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

from .scaling_mechanism_description_py3 import ScalingMechanismDescription


class AddRemoveIncrementalNamedPartitionScalingMechanism(ScalingMechanismDescription):
    """Represents a scaling mechanism for adding or removing named partitions of a
    stateless service. Partition names are in the format '0','1''N-1'.

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    :param min_partition_count: Required. Minimum number of named partitions
     of the service.
    :type min_partition_count: int
    :param max_partition_count: Required. Maximum number of named partitions
     of the service.
    :type max_partition_count: int
    :param scale_increment: Required. The number of instances to add or remove
     during a scaling operation.
    :type scale_increment: int
    """

    _validation = {
        'kind': {'required': True},
        'min_partition_count': {'required': True},
        'max_partition_count': {'required': True},
        'scale_increment': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'Kind', 'type': 'str'},
        'min_partition_count': {'key': 'MinPartitionCount', 'type': 'int'},
        'max_partition_count': {'key': 'MaxPartitionCount', 'type': 'int'},
        'scale_increment': {'key': 'ScaleIncrement', 'type': 'int'},
    }

    def __init__(self, *, min_partition_count: int, max_partition_count: int, scale_increment: int, **kwargs) -> None:
        super(AddRemoveIncrementalNamedPartitionScalingMechanism, self).__init__(**kwargs)
        self.min_partition_count = min_partition_count
        self.max_partition_count = max_partition_count
        self.scale_increment = scale_increment
        self.kind = 'AddRemoveIncrementalNamedPartition'
