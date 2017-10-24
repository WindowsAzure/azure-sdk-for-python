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


class RuleCondition(Model):
    """The condition that results in the alert rule being activated.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: ThresholdRuleCondition, LocationThresholdRuleCondition,
    ManagementEventRuleCondition

    :param data_source: the resource from which the rule collects its data.
     For this type dataSource will always be of type RuleMetricDataSource.
    :type data_source: ~azure.mgmt.monitor.models.RuleDataSource
    :param odatatype: Constant filled by server.
    :type odatatype: str
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'data_source': {'key': 'dataSource', 'type': 'RuleDataSource'},
        'odatatype': {'key': 'odata\\.type', 'type': 'str'},
    }

    _subtype_map = {
        'odatatype': {'Microsoft.Azure.Management.Insights.Models.ThresholdRuleCondition': 'ThresholdRuleCondition', 'Microsoft.Azure.Management.Insights.Models.LocationThresholdRuleCondition': 'LocationThresholdRuleCondition', 'Microsoft.Azure.Management.Insights.Models.ManagementEventRuleCondition': 'ManagementEventRuleCondition'}
    }

    def __init__(self, data_source=None):
        self.data_source = data_source
        self.odatatype = None
