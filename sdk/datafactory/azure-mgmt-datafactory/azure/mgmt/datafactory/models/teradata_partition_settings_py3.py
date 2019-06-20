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


class TeradataPartitionSettings(Model):
    """The settings that will be leveraged for teradata source partitioning.

    :param partition_column_name: The name of the column in integer type that
     will be used for proceeding range or hash partitioning. Type: string (or
     Expression with resultType string).
    :type partition_column_name: object
    :param partition_upper_bound: The maximum value of column specified in
     partitionColumnName that will be used for proceeding range partitioning.
     Type: string (or Expression with resultType string).
    :type partition_upper_bound: object
    :param partition_lower_bound: The minimum value of column specified in
     partitionColumnName that will be used for proceeding range partitioning.
     Type: string (or Expression with resultType string).
    :type partition_lower_bound: object
    """

    _attribute_map = {
        'partition_column_name': {'key': 'partitionColumnName', 'type': 'object'},
        'partition_upper_bound': {'key': 'partitionUpperBound', 'type': 'object'},
        'partition_lower_bound': {'key': 'partitionLowerBound', 'type': 'object'},
    }

    def __init__(self, *, partition_column_name=None, partition_upper_bound=None, partition_lower_bound=None, **kwargs) -> None:
        super(TeradataPartitionSettings, self).__init__(**kwargs)
        self.partition_column_name = partition_column_name
        self.partition_upper_bound = partition_upper_bound
        self.partition_lower_bound = partition_lower_bound
