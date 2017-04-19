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

from .rule_condition import RuleCondition


class ThresholdRuleCondition(RuleCondition):
    """A rule condition based on a metric crossing a threshold.

    :param odatatype: Polymorphic Discriminator
    :type odatatype: str
    :param data_source: the resource from which the rule collects its data.
     For this type dataSource will always be of type RuleMetricDataSource.
    :type data_source: :class:`RuleDataSource
     <azure.mgmt.monitor.models.RuleDataSource>`
    :param operator: the operator used to compare the data and the threshold.
     Possible values include: 'GreaterThan', 'GreaterThanOrEqual', 'LessThan',
     'LessThanOrEqual'
    :type operator: str or :class:`ConditionOperator
     <azure.mgmt.monitor.models.ConditionOperator>`
    :param threshold: the threshold value that activates the alert.
    :type threshold: float
    :param window_size: the period of time (in ISO 8601 duration format) that
     is used to monitor alert activity based on the threshold. If specified
     then it must be between 5 minutes and 1 day.
    :type window_size: timedelta
    :param time_aggregation: the time aggregation operator. How the data that
     are collected should be combined over time. The default value is the
     PrimaryAggregationType of the Metric. Possible values include: 'Average',
     'Minimum', 'Maximum', 'Total', 'Last'
    :type time_aggregation: str or :class:`TimeAggregationOperator
     <azure.mgmt.monitor.models.TimeAggregationOperator>`
    """

    _validation = {
        'odatatype': {'required': True},
        'operator': {'required': True},
        'threshold': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': 'odata\\.type', 'type': 'str'},
        'data_source': {'key': 'dataSource', 'type': 'RuleDataSource'},
        'operator': {'key': 'operator', 'type': 'ConditionOperator'},
        'threshold': {'key': 'threshold', 'type': 'float'},
        'window_size': {'key': 'windowSize', 'type': 'duration'},
        'time_aggregation': {'key': 'timeAggregation', 'type': 'TimeAggregationOperator'},
    }

    def __init__(self, operator, threshold, data_source=None, window_size=None, time_aggregation=None):
        super(ThresholdRuleCondition, self).__init__()
        self.data_source = data_source
        self.operator = operator
        self.threshold = threshold
        self.window_size = window_size
        self.time_aggregation = time_aggregation
        self.odatatype = 'Microsoft.Azure.Management.Insights.Models.ThresholdRuleCondition'
