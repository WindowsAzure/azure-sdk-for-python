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


class FusionAlertRuleTemplate(AlertRuleTemplate):
    """Represents fusion alert rule template.

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
    :param display_name: The display name for alert rule template.
    :type display_name: str
    :param description: The description of the alert rule template.
    :type description: str
    :param tactics: The tactics of the alert rule template
    :type tactics: list[str or
     ~azure.mgmt.securityinsight.models.AttackTactic]
    :ivar created_date_utc: The time that this alert rule template has been
     added.
    :vartype created_date_utc: str
    :param status: The alert rule template status. Possible values include:
     'Installed', 'Available', 'NotAvailable'
    :type status: str or ~azure.mgmt.securityinsight.models.TemplateStatus
    :param required_data_connectors: The required data connectors for this
     template
    :type required_data_connectors:
     list[~azure.mgmt.securityinsight.models.DataConnectorStatus]
    :param alert_rules_created_by_template_count: the number of alert rules
     that were created by this template
    :type alert_rules_created_by_template_count: int
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'kind': {'required': True},
        'created_date_utc': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'tactics': {'key': 'properties.tactics', 'type': '[AttackTactic]'},
        'created_date_utc': {'key': 'properties.createdDateUTC', 'type': 'str'},
        'status': {'key': 'properties.status', 'type': 'TemplateStatus'},
        'required_data_connectors': {'key': 'properties.requiredDataConnectors', 'type': '[DataConnectorStatus]'},
        'alert_rules_created_by_template_count': {'key': 'properties.alertRulesCreatedByTemplateCount', 'type': 'int'},
    }

    def __init__(self, *, etag: str=None, display_name: str=None, description: str=None, tactics=None, status=None, required_data_connectors=None, alert_rules_created_by_template_count: int=None, **kwargs) -> None:
        super(FusionAlertRuleTemplate, self).__init__(etag=etag, **kwargs)
        self.display_name = display_name
        self.description = description
        self.tactics = tactics
        self.created_date_utc = None
        self.status = status
        self.required_data_connectors = required_data_connectors
        self.alert_rules_created_by_template_count = alert_rules_created_by_template_count
        self.kind = 'Fusion'
