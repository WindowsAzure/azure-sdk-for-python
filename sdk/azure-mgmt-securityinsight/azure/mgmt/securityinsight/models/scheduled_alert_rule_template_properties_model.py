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


class ScheduledAlertRuleTemplatePropertiesModel(Model):
    """Schedule alert rule template property bag.

    :param severity: The severity for alerts created by this alert rule.
     Possible values include: 'High', 'Medium', 'Low', 'Informational'
    :type severity: str or ~azure.mgmt.securityinsight.models.AlertSeverity
    :param query: The query that creates alerts for this rule.
    :type query: str
    :param query_frequency: The frequency (in ISO 8601 duration format) for
     this alert rule to run.
    :type query_frequency: timedelta
    :param query_period: The period (in ISO 8601 duration format) that this
     alert rule looks at.
    :type query_period: timedelta
    :param trigger_operator: The operation against the threshold that triggers
     alert rule. Possible values include: 'GreaterThan', 'LessThan', 'Equal',
     'NotEqual'
    :type trigger_operator: str or
     ~azure.mgmt.securityinsight.models.TriggerOperator
    :param trigger_threshold: The threshold triggers this alert rule.
    :type trigger_threshold: int
    """

    _attribute_map = {
        'severity': {'key': 'severity', 'type': 'AlertSeverity'},
        'query': {'key': 'query', 'type': 'str'},
        'query_frequency': {'key': 'queryFrequency', 'type': 'duration'},
        'query_period': {'key': 'queryPeriod', 'type': 'duration'},
        'trigger_operator': {'key': 'triggerOperator', 'type': 'TriggerOperator'},
        'trigger_threshold': {'key': 'triggerThreshold', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(ScheduledAlertRuleTemplatePropertiesModel, self).__init__(**kwargs)
        self.severity = kwargs.get('severity', None)
        self.query = kwargs.get('query', None)
        self.query_frequency = kwargs.get('query_frequency', None)
        self.query_period = kwargs.get('query_period', None)
        self.trigger_operator = kwargs.get('trigger_operator', None)
        self.trigger_threshold = kwargs.get('trigger_threshold', None)
