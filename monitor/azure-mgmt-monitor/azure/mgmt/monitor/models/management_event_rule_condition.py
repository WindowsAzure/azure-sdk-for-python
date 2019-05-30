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


class ManagementEventRuleCondition(RuleCondition):
    """A management event rule condition.

    All required parameters must be populated in order to send to Azure.

    :param data_source: the resource from which the rule collects its data.
     For this type dataSource will always be of type RuleMetricDataSource.
    :type data_source: ~azure.mgmt.monitor.models.RuleDataSource
    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param aggregation: How the data that is collected should be combined over
     time and when the alert is activated. Note that for management event
     alerts aggregation is optional – if it is not provided then any event will
     cause the alert to activate.
    :type aggregation:
     ~azure.mgmt.monitor.models.ManagementEventAggregationCondition
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'data_source': {'key': 'dataSource', 'type': 'RuleDataSource'},
        'odatatype': {'key': 'odata\\.type', 'type': 'str'},
        'aggregation': {'key': 'aggregation', 'type': 'ManagementEventAggregationCondition'},
    }

    def __init__(self, **kwargs):
        super(ManagementEventRuleCondition, self).__init__(**kwargs)
        self.aggregation = kwargs.get('aggregation', None)
        self.odatatype = 'Microsoft.Azure.Management.Insights.Models.ManagementEventRuleCondition'
