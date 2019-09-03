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

from .alert_rule_template import AlertRuleTemplate


class FilterAlertRuleTemplate(AlertRuleTemplate):
    """Represents filter alert rule template.

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
    :param required_data_connectors: The required data connectors for this
     template
    :type required_data_connectors:
     list[~azure.mgmt.securityinsight.models.DataConnectorStatus]
    :param status: Required. The alert rule template status. Possible values
     include: 'Installed', 'Available', 'NotAvailable'
    :type status: str or ~azure.mgmt.securityinsight.models.TemplateStatus
    :param tactics: The tactics of the alert rule template
    :type tactics: list[str or
     ~azure.mgmt.securityinsight.models.AttackTactic]
    :param filter_product: Required. The filter product name for this template
     rule.
    :type filter_product: str
    :param filter_severities: the alert’s severities on which the cases will
     be generated
    :type filter_severities: list[str or
     ~azure.mgmt.securityinsight.models.AlertSeverity]
    :param filter_titles: the alert’s titles on which the cases will be
     generated
    :type filter_titles: list[str]
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
        'status': {'required': True},
        'filter_product': {'required': True},
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
        'filter_product': {'key': 'properties.filterProduct', 'type': 'str'},
        'filter_severities': {'key': 'properties.filterSeverities', 'type': '[AlertSeverity]'},
        'filter_titles': {'key': 'properties.filterTitles', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(FilterAlertRuleTemplate, self).__init__(**kwargs)
        self.alert_rules_created_by_template_count = kwargs.get('alert_rules_created_by_template_count', None)
        self.created_date_utc = None
        self.description = kwargs.get('description', None)
        self.display_name = kwargs.get('display_name', None)
        self.required_data_connectors = kwargs.get('required_data_connectors', None)
        self.status = kwargs.get('status', None)
        self.tactics = kwargs.get('tactics', None)
        self.filter_product = kwargs.get('filter_product', None)
        self.filter_severities = kwargs.get('filter_severities', None)
        self.filter_titles = kwargs.get('filter_titles', None)
        self.kind = 'Filter'
