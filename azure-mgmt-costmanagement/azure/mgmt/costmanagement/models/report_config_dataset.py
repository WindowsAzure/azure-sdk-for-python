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


class ReportConfigDataset(Model):
    """The definition of data present in the report.

    :param granularity: The granularity of rows in the report. Possible values
     include: 'Daily'
    :type granularity: str or
     ~azure.mgmt.costmanagement.models.GranularityType
    :param configuration: Has configuration information for the data in the
     report. The configuration will be ignored if aggregation and grouping are
     provided.
    :type configuration:
     ~azure.mgmt.costmanagement.models.ReportConfigDatasetConfiguration
    :param aggregation: Dictionary of aggregation expression to use in the
     report. The key of each item in the dictionary is the alias for the
     aggregated column. Report can have up to 2 aggregation clauses.
    :type aggregation: dict[str,
     ~azure.mgmt.costmanagement.models.ReportConfigAggregation]
    :param grouping: Array of group by expression to use in the report. Report
     can have up to 2 group by clauses.
    :type grouping:
     list[~azure.mgmt.costmanagement.models.ReportConfigGrouping]
    :param filter: Has filter expression to use in the report.
    :type filter: ~azure.mgmt.costmanagement.models.ReportConfigFilter
    """

    _validation = {
        'grouping': {'max_items': 2},
    }

    _attribute_map = {
        'granularity': {'key': 'granularity', 'type': 'str'},
        'configuration': {'key': 'configuration', 'type': 'ReportConfigDatasetConfiguration'},
        'aggregation': {'key': 'aggregation', 'type': '{ReportConfigAggregation}'},
        'grouping': {'key': 'grouping', 'type': '[ReportConfigGrouping]'},
        'filter': {'key': 'filter', 'type': 'ReportConfigFilter'},
    }

    def __init__(self, **kwargs):
        super(ReportConfigDataset, self).__init__(**kwargs)
        self.granularity = kwargs.get('granularity', None)
        self.configuration = kwargs.get('configuration', None)
        self.aggregation = kwargs.get('aggregation', None)
        self.grouping = kwargs.get('grouping', None)
        self.filter = kwargs.get('filter', None)
