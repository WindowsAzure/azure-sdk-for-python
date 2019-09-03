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

from .alert_rule_template_py3 import AlertRuleTemplate


class ScheduledAlertRuleTemplate(AlertRuleTemplate):
    """Represents scheduled alert rule template.

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
    :param alert_rules_created_by_template_count: Required. the number of
     alert rules that were created by this template
    :type alert_rules_created_by_template_count: int
    :ivar created_date_utc: Required. The time that this alert rule template
     has been added.
    :vartype created_date_utc: str
    :param description: Required. The description of the alert rule template.
    :type description: str
    :param display_name: Required. The display name for alert rule template.
    :type display_name: str
    :param required_data_connectors: Required. The required data connectors
     for this template
    :type required_data_connectors:
     list[~azure.mgmt.securityinsight.models.DataConnectorStatus]
    :param status: Required. The alert rule template status. Possible values
     include: 'Installed', 'Available', 'NotAvailable'
    :type status: str or ~azure.mgmt.securityinsight.models.TemplateStatus
    :param tactics: The tactics of the alert rule template
    :type tactics: list[str or
     ~azure.mgmt.securityinsight.models.AttackTactic]
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
        'alert_rules_created_by_template_count': {'required': True},
        'created_date_utc': {'required': True, 'readonly': True},
        'description': {'required': True},
        'display_name': {'required': True},
        'required_data_connectors': {'required': True},
        'status': {'required': True},
        'query': {'required': True},
        'query_frequency': {'required': True},
        'query_period': {'required': True},
        'severity': {'required': True},
        'trigger_operator': {'required': True},
        'trigger_threshold': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'alert_rules_created_by_template_count': {'key': 'properties.alertRulesCreatedByTemplateCount', 'type': 'int'},
        'created_date_utc': {'key': 'properties.createdDateUTC', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'required_data_connectors': {'key': 'properties.requiredDataConnectors', 'type': '[DataConnectorStatus]'},
        'status': {'key': 'properties.status', 'type': 'TemplateStatus'},
        'tactics': {'key': 'properties.tactics', 'type': '[AttackTactic]'},
        'query': {'key': 'properties.query', 'type': 'str'},
        'query_frequency': {'key': 'properties.queryFrequency', 'type': 'duration'},
        'query_period': {'key': 'properties.queryPeriod', 'type': 'duration'},
        'severity': {'key': 'properties.severity', 'type': 'AlertSeverity'},
        'trigger_operator': {'key': 'properties.triggerOperator', 'type': 'TriggerOperator'},
        'trigger_threshold': {'key': 'properties.triggerThreshold', 'type': 'int'},
    }

    def __init__(self, *, alert_rules_created_by_template_count: int, description: str, display_name: str, required_data_connectors, status, query: str, query_frequency, query_period, severity, trigger_operator, trigger_threshold: int, etag: str=None, tactics=None, **kwargs) -> None:
        super(ScheduledAlertRuleTemplate, self).__init__(etag=etag, **kwargs)
        self.alert_rules_created_by_template_count = alert_rules_created_by_template_count
        self.created_date_utc = None
        self.description = description
        self.display_name = display_name
        self.required_data_connectors = required_data_connectors
        self.status = status
        self.tactics = tactics
        self.query = query
        self.query_frequency = query_frequency
        self.query_period = query_period
        self.severity = severity
        self.trigger_operator = trigger_operator
        self.trigger_threshold = trigger_threshold
        self.kind = 'Scheduled'
