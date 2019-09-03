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

from .alert_rule_py3 import AlertRule


class ScheduledAlertRule(AlertRule):
    """Represents scheduled alert rule.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param etag: Etag of the alert rule.
    :type etag: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param description: Required. The description of the alert rule.
    :type description: str
    :param display_name: Required. The display name for alerts created by this
     alert rule.
    :type display_name: str
    :param enabled: Required. Determines whether this alert rule is enabled or
     disabled.
    :type enabled: bool
    :ivar last_modified_utc: The last time that this alert has been modified.
    :vartype last_modified_utc: str
    :param query: Required. The query that creates alerts for this rule.
    :type query: str
    :param query_frequency: Required. The frequency (in ISO 8601 duration
     format) for this alert rule to run.
    :type query_frequency: timedelta
    :param query_period: Required. The period (in ISO 8601 duration format)
     that this alert rule looks at.
    :type query_period: timedelta
    :param severity: Required. The severity for alerts created by this alert
     rule. Possible values include: 'High', 'Medium', 'Low', 'Informational'
    :type severity: str or ~azure.mgmt.securityinsight.models.AlertSeverity
    :param suppression_duration: Required. The suppression (in ISO 8601
     duration format) to wait since last time this alert rule been triggered.
    :type suppression_duration: timedelta
    :param suppression_enabled: Required. Determines whether the suppression
     for this alert rule is enabled or disabled.
    :type suppression_enabled: bool
    :param trigger_operator: Required. The operation against the threshold
     that triggers alert rule. Possible values include: 'GreaterThan',
     'LessThan', 'Equal', 'NotEqual'
    :type trigger_operator: str or
     ~azure.mgmt.securityinsight.models.TriggerOperator
    :param trigger_threshold: Required. The threshold triggers this alert
     rule.
    :type trigger_threshold: int
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'kind': {'required': True},
        'description': {'required': True},
        'display_name': {'required': True},
        'enabled': {'required': True},
        'last_modified_utc': {'readonly': True},
        'query': {'required': True},
        'query_frequency': {'required': True},
        'query_period': {'required': True},
        'severity': {'required': True},
        'suppression_duration': {'required': True},
        'suppression_enabled': {'required': True},
        'trigger_operator': {'required': True},
        'trigger_threshold': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'last_modified_utc': {'key': 'properties.lastModifiedUtc', 'type': 'str'},
        'query': {'key': 'properties.query', 'type': 'str'},
        'query_frequency': {'key': 'properties.queryFrequency', 'type': 'duration'},
        'query_period': {'key': 'properties.queryPeriod', 'type': 'duration'},
        'severity': {'key': 'properties.severity', 'type': 'AlertSeverity'},
        'suppression_duration': {'key': 'properties.suppressionDuration', 'type': 'duration'},
        'suppression_enabled': {'key': 'properties.suppressionEnabled', 'type': 'bool'},
        'trigger_operator': {'key': 'properties.triggerOperator', 'type': 'TriggerOperator'},
        'trigger_threshold': {'key': 'properties.triggerThreshold', 'type': 'int'},
    }

    def __init__(self, *, description: str, display_name: str, enabled: bool, query: str, query_frequency, query_period, severity, suppression_duration, suppression_enabled: bool, trigger_operator, trigger_threshold: int, etag: str=None, **kwargs) -> None:
        super(ScheduledAlertRule, self).__init__(etag=etag, **kwargs)
        self.description = description
        self.display_name = display_name
        self.enabled = enabled
        self.last_modified_utc = None
        self.query = query
        self.query_frequency = query_frequency
        self.query_period = query_period
        self.severity = severity
        self.suppression_duration = suppression_duration
        self.suppression_enabled = suppression_enabled
        self.trigger_operator = trigger_operator
        self.trigger_threshold = trigger_threshold
        self.kind = 'Scheduled'
