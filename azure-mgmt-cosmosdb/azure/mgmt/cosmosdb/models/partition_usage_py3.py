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

from .usage_py3 import Usage


class PartitionUsage(Usage):
    """The partition level usage data for a usage request.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param unit: The unit of the metric. Possible values include: 'Count',
     'Bytes', 'Seconds', 'Percent', 'CountPerSecond', 'BytesPerSecond',
     'Milliseconds'
    :type unit: str or ~azure.mgmt.cosmosdb.models.UnitType
    :ivar name: The name information for the metric.
    :vartype name: ~azure.mgmt.cosmosdb.models.MetricName
    :ivar quota_period: The quota period used to summarize the usage values.
    :vartype quota_period: str
    :ivar limit: Maximum value for this metric
    :vartype limit: long
    :ivar current_value: Current value for this metric
    :vartype current_value: long
    :ivar partition_id: The partition id (GUID identifier) of the usages.
    :vartype partition_id: str
    :ivar partition_key_range_id: The partition key range id (integer
     identifier) of the usages.
    :vartype partition_key_range_id: str
    """

    _validation = {
        'name': {'readonly': True},
        'quota_period': {'readonly': True},
        'limit': {'readonly': True},
        'current_value': {'readonly': True},
        'partition_id': {'readonly': True},
        'partition_key_range_id': {'readonly': True},
    }

    _attribute_map = {
        'unit': {'key': 'unit', 'type': 'str'},
        'name': {'key': 'name', 'type': 'MetricName'},
        'quota_period': {'key': 'quotaPeriod', 'type': 'str'},
        'limit': {'key': 'limit', 'type': 'long'},
        'current_value': {'key': 'currentValue', 'type': 'long'},
        'partition_id': {'key': 'partitionId', 'type': 'str'},
        'partition_key_range_id': {'key': 'partitionKeyRangeId', 'type': 'str'},
    }

    def __init__(self, *, unit=None, **kwargs) -> None:
        super(PartitionUsage, self).__init__(unit=unit, **kwargs)
        self.partition_id = None
        self.partition_key_range_id = None
