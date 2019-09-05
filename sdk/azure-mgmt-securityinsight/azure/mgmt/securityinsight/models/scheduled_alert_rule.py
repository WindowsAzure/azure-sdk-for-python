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

    :param etag: Etag of the azure resource
    :type etag: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param query: The query that creates alerts for this rule.
    :type query: str
    :param query_frequency: The frequency (in ISO 8601 duration format) for
     this alert rule to run.
    :type query_frequency: timedelta
    :param query_period: The period (in ISO 8601 duration format) that this
     alert rule looks at.
    :type query_period: timedelta
    :param severity: The severity for alerts created by this alert rule.
     Possible values include: 'High', 'Medium', 'Low', 'Informational'
    :type severity: str or ~azure.mgmt.securityinsight.models.AlertSeverity
    :param trigger_operator: The operation against the threshold that triggers
     alert rule. Possible values include: 'GreaterThan', 'LessThan', 'Equal',
     'NotEqual'
    :type trigger_operator: str or
     ~azure.mgmt.securityinsight.models.TriggerOperator
    :param trigger_threshold: The threshold triggers this alert rule.
    :type trigger_threshold: int
    :param alert_rule_template_name: The Name of the alert rule template used
     to create this rule.
    :type alert_rule_template_name: str
    :param description: The description of the alert rule.
    :type description: str
    :param display_name: Required. The display name for alerts created by this
     alert rule.
    :type display_name: str
    :param enabled: Required. Determines whether this alert rule is enabled or
     disabled.
    :type enabled: bool
    :ivar last_modified_utc: The last time that this alert rule has been
     modified.
    :vartype last_modified_utc: str
    :param suppression_duration: Required. The suppression (in ISO 8601
     duration format) to wait since last time this alert rule been triggered.
    :type suppression_duration: timedelta
    :param suppression_enabled: Required. Determines whether the suppression
     for this alert rule is enabled or disabled.
    :type suppression_enabled: bool
    :param tactics: The tactics of the alert rule
    :type tactics: list[str or
     ~azure.mgmt.securityinsight.models.AttackTactic]
    """

    _validation = {
        'kind': {'required': True},
        'display_name': {'required': True},
        'enabled': {'required': True},
        'last_modified_utc': {'readonly': True},
        'suppression_duration': {'required': True},
        'suppression_enabled': {'required': True},
    }

    _attribute_map = {
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'query': {'key': 'properties.query', 'type': 'str'},
        'query_frequency': {'key': 'properties.queryFrequency', 'type': 'duration'},
        'query_period': {'key': 'properties.queryPeriod', 'type': 'duration'},
        'severity': {'key': 'properties.severity', 'type': 'str'},
        'trigger_operator': {'key': 'properties.triggerOperator', 'type': 'TriggerOperator'},
        'trigger_threshold': {'key': 'properties.triggerThreshold', 'type': 'int'},
        'alert_rule_template_name': {'key': 'properties.alertRuleTemplateName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'last_modified_utc': {'key': 'properties.lastModifiedUtc', 'type': 'str'},
        'suppression_duration': {'key': 'properties.suppressionDuration', 'type': 'duration'},
        'suppression_enabled': {'key': 'properties.suppressionEnabled', 'type': 'bool'},
        'tactics': {'key': 'properties.tactics', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ScheduledAlertRule, self).__init__(**kwargs)
        self.query = kwargs.get('query', None)
        self.query_frequency = kwargs.get('query_frequency', None)
        self.query_period = kwargs.get('query_period', None)
        self.severity = kwargs.get('severity', None)
        self.trigger_operator = kwargs.get('trigger_operator', None)
        self.trigger_threshold = kwargs.get('trigger_threshold', None)
        self.alert_rule_template_name = kwargs.get('alert_rule_template_name', None)
        self.description = kwargs.get('description', None)
        self.display_name = kwargs.get('display_name', None)
        self.enabled = kwargs.get('enabled', None)
        self.last_modified_utc = None
        self.suppression_duration = kwargs.get('suppression_duration', None)
        self.suppression_enabled = kwargs.get('suppression_enabled', None)
        self.tactics = kwargs.get('tactics', None)
        self.kind = 'Scheduled'
