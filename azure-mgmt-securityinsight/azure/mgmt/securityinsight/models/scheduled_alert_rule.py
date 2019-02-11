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

from .alert_rule import AlertRule


class ScheduledAlertRule(AlertRule):
    """Represents scheduled alert rule.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar type: Azure resource type
    :vartype type: str
    :ivar name: Azure resource name
    :vartype name: str
    :param etag: Etag of the alert rule.
    :type etag: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param rule_name: Required. The name for alerts created by this alert
     rule.
    :type rule_name: str
    :param description: Required. The description of the alert rule.
    :type description: str
    :param severity: Required. The severity for alerts created by this alert
     rule. Possible values include: 'High', 'Medium', 'Low', 'Informational'
    :type severity: str or ~azure.mgmt.securityinsight.models.AlertSeverity
    :param enabled: Required. Determines whether this alert rule is enabled or
     disabled.
    :type enabled: bool
    :param query: Required. The query that creates alerts for this rule.
    :type query: str
    :param query_frequency: Required. The frequency (in ISO 8601 duration
     format) for this alert rule to run.
    :type query_frequency: timedelta
    :param query_period: Required. The period (in ISO 8601 duration format)
     that this alert rule looks at.
    :type query_period: timedelta
    :param trigger_operator: Required. The operation against the threshold
     that triggers alert rule. Possible values include: 'GreaterThan',
     'LessThan', 'Equal', 'NotEqual'
    :type trigger_operator: str or
     ~azure.mgmt.securityinsight.models.TriggerOperator
    :param trigger_threshold: Required. The threshold triggers this alert
     rule.
    :type trigger_threshold: int
    :param suppression_enabled: Required. Determines whether the suppression
     for this alert rule is enabled or disabled.
    :type suppression_enabled: bool
    :param suppression_duration: Required. The suppression (in ISO 8601
     duration format) to wait since last time this alert rule been triggered.
    :type suppression_duration: timedelta
    :ivar last_modified_utc: The last time that this alert has been modified.
    :vartype last_modified_utc: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'kind': {'required': True},
        'rule_name': {'required': True},
        'description': {'required': True},
        'severity': {'required': True},
        'enabled': {'required': True},
        'query': {'required': True},
        'query_frequency': {'required': True},
        'query_period': {'required': True},
        'trigger_operator': {'required': True},
        'trigger_threshold': {'required': True},
        'suppression_enabled': {'required': True},
        'suppression_duration': {'required': True},
        'last_modified_utc': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'rule_name': {'key': 'properties.ruleName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'severity': {'key': 'properties.severity', 'type': 'AlertSeverity'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'query': {'key': 'properties.query', 'type': 'str'},
        'query_frequency': {'key': 'properties.queryFrequency', 'type': 'duration'},
        'query_period': {'key': 'properties.queryPeriod', 'type': 'duration'},
        'trigger_operator': {'key': 'properties.triggerOperator', 'type': 'TriggerOperator'},
        'trigger_threshold': {'key': 'properties.triggerThreshold', 'type': 'int'},
        'suppression_enabled': {'key': 'properties.suppressionEnabled', 'type': 'bool'},
        'suppression_duration': {'key': 'properties.suppressionDuration', 'type': 'duration'},
        'last_modified_utc': {'key': 'properties.lastModifiedUtc', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ScheduledAlertRule, self).__init__(**kwargs)
        self.rule_name = kwargs.get('rule_name', None)
        self.description = kwargs.get('description', None)
        self.severity = kwargs.get('severity', None)
        self.enabled = kwargs.get('enabled', None)
        self.query = kwargs.get('query', None)
        self.query_frequency = kwargs.get('query_frequency', None)
        self.query_period = kwargs.get('query_period', None)
        self.trigger_operator = kwargs.get('trigger_operator', None)
        self.trigger_threshold = kwargs.get('trigger_threshold', None)
        self.suppression_enabled = kwargs.get('suppression_enabled', None)
        self.suppression_duration = kwargs.get('suppression_duration', None)
        self.last_modified_utc = None
        self.kind = 'Scheduled'
