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

from .metric import Metric


class PartitionMetric(Metric):
    """The metric values for a single partition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar start_time: The start time for the metric (ISO-8601 format).
    :vartype start_time: datetime
    :ivar end_time: The end time for the metric (ISO-8601 format).
    :vartype end_time: datetime
    :ivar time_grain: The time grain to be used to summarize the metric
     values.
    :vartype time_grain: str
    :param unit: The unit of the metric. Possible values include: 'Count',
     'Bytes', 'Seconds', 'Percent', 'CountPerSecond', 'BytesPerSecond',
     'Milliseconds'
    :type unit: str or ~azure.mgmt.cosmosdb.models.UnitType
    :ivar name: The name information for the metric.
    :vartype name: ~azure.mgmt.cosmosdb.models.MetricName
    :ivar metric_values: The metric values for the specified time window and
     timestep.
    :vartype metric_values: list[~azure.mgmt.cosmosdb.models.MetricValue]
    :ivar partition_id: The parition id (GUID identifier) of the metric
     values.
    :vartype partition_id: str
    :ivar partition_key_range_id: The partition key range id (integer
     identifier) of the metric values.
    :vartype partition_key_range_id: str
    """

    _validation = {
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
        'time_grain': {'readonly': True},
        'name': {'readonly': True},
        'metric_values': {'readonly': True},
        'partition_id': {'readonly': True},
        'partition_key_range_id': {'readonly': True},
    }

    _attribute_map = {
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'time_grain': {'key': 'timeGrain', 'type': 'str'},
        'unit': {'key': 'unit', 'type': 'str'},
        'name': {'key': 'name', 'type': 'MetricName'},
        'metric_values': {'key': 'metricValues', 'type': '[MetricValue]'},
        'partition_id': {'key': 'partitionId', 'type': 'str'},
        'partition_key_range_id': {'key': 'partitionKeyRangeId', 'type': 'str'},
    }

    def __init__(self, *, unit=None, **kwargs) -> None:
        super(PartitionMetric, self).__init__(unit=unit, **kwargs)
        self.partition_id = None
        self.partition_key_range_id = None
