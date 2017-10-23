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


class ServiceDiagnosticSettingsResourcePatch(Model):
    """Service diagnostic setting resource for patch operations.

    :param tags: Resource tags
    :type tags: dict
    :param storage_account_id: The resource ID of the storage account to which
     you would like to send Diagnostic Logs.
    :type storage_account_id: str
    :param service_bus_rule_id: The service bus rule ID of the service bus
     namespace in which you would like to have Event Hubs created for streaming
     Diagnostic Logs. The rule ID is of the format: '{service bus resource
     ID}/authorizationrules/{key name}'.
    :type service_bus_rule_id: str
    :param event_hub_authorization_rule_id: The resource Id for the event hub
     namespace authorization rule.
    :type event_hub_authorization_rule_id: str
    :param metrics: the list of metric settings.
    :type metrics: list of :class:`MetricSettings
     <azure.mgmt.monitor.models.MetricSettings>`
    :param logs: the list of logs settings.
    :type logs: list of :class:`LogSettings
     <azure.mgmt.monitor.models.LogSettings>`
    :param workspace_id: The workspace ID (resource ID of a Log Analytics
     workspace) for a Log Analytics workspace to which you would like to send
     Diagnostic Logs. Example:
     /subscriptions/4b9e8510-67ab-4e9a-95a9-e2f1e570ea9c/resourceGroups/insights-integration/providers/Microsoft.OperationalInsights/workspaces/viruela2
    :type workspace_id: str
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'storage_account_id': {'key': 'properties.storageAccountId', 'type': 'str'},
        'service_bus_rule_id': {'key': 'properties.serviceBusRuleId', 'type': 'str'},
        'event_hub_authorization_rule_id': {'key': 'properties.eventHubAuthorizationRuleId', 'type': 'str'},
        'metrics': {'key': 'properties.metrics', 'type': '[MetricSettings]'},
        'logs': {'key': 'properties.logs', 'type': '[LogSettings]'},
        'workspace_id': {'key': 'properties.workspaceId', 'type': 'str'},
    }

    def __init__(self, tags=None, storage_account_id=None, service_bus_rule_id=None, event_hub_authorization_rule_id=None, metrics=None, logs=None, workspace_id=None):
        self.tags = tags
        self.storage_account_id = storage_account_id
        self.service_bus_rule_id = service_bus_rule_id
        self.event_hub_authorization_rule_id = event_hub_authorization_rule_id
        self.metrics = metrics
        self.logs = logs
        self.workspace_id = workspace_id
