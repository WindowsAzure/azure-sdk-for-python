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


class QueryDefinition(Model):
    """The definition of a query.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar type: Required. The type of the query. Default value: "Usage" .
    :vartype type: str
    :param timeframe: Required. The time frame for pulling data for the query.
     If custom, then a specific time period must be provided. Possible values
     include: 'WeekToDate', 'MonthToDate', 'YearToDate', 'TheLastWeek',
     'TheLastMonth', 'TheLastYear', 'Custom'
    :type timeframe: str or ~azure.mgmt.costmanagement.models.TimeframeType
    :param time_period: Has time period for pulling data for the query.
    :type time_period: ~azure.mgmt.costmanagement.models.QueryTimePeriod
    :param dataset: Has definition for data in this query.
    :type dataset: ~azure.mgmt.costmanagement.models.QueryDataset
    """

    _validation = {
        'type': {'required': True, 'constant': True},
        'timeframe': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'timeframe': {'key': 'timeframe', 'type': 'str'},
        'time_period': {'key': 'timePeriod', 'type': 'QueryTimePeriod'},
        'dataset': {'key': 'dataset', 'type': 'QueryDataset'},
    }

    type = "Usage"

    def __init__(self, *, timeframe, time_period=None, dataset=None, **kwargs) -> None:
        super(QueryDefinition, self).__init__(**kwargs)
        self.timeframe = timeframe
        self.time_period = time_period
        self.dataset = dataset
