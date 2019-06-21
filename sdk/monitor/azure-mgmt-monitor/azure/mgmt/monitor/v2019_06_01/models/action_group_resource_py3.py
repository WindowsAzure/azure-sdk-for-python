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

from .resource_py3 import Resource


class ActionGroupResource(Resource):
    """An action group resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param group_short_name: Required. The short name of the action group.
     This will be used in SMS messages.
    :type group_short_name: str
    :param enabled: Required. Indicates whether this action group is enabled.
     If an action group is not enabled, then none of its receivers will receive
     communications. Default value: True .
    :type enabled: bool
    :param email_receivers: The list of email receivers that are part of this
     action group.
    :type email_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.EmailReceiver]
    :param sms_receivers: The list of SMS receivers that are part of this
     action group.
    :type sms_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.SmsReceiver]
    :param webhook_receivers: The list of webhook receivers that are part of
     this action group.
    :type webhook_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.WebhookReceiver]
    :param itsm_receivers: The list of ITSM receivers that are part of this
     action group.
    :type itsm_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.ItsmReceiver]
    :param azure_app_push_receivers: The list of AzureAppPush receivers that
     are part of this action group.
    :type azure_app_push_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.AzureAppPushReceiver]
    :param automation_runbook_receivers: The list of AutomationRunbook
     receivers that are part of this action group.
    :type automation_runbook_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.AutomationRunbookReceiver]
    :param voice_receivers: The list of voice receivers that are part of this
     action group.
    :type voice_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.VoiceReceiver]
    :param logic_app_receivers: The list of logic app receivers that are part
     of this action group.
    :type logic_app_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.LogicAppReceiver]
    :param azure_function_receivers: The list of azure function receivers that
     are part of this action group.
    :type azure_function_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.AzureFunctionReceiver]
    :param arm_role_receivers: The list of ARM role receivers that are part of
     this action group. Roles are Azure RBAC roles and only built-in roles are
     supported.
    :type arm_role_receivers:
     list[~azure.mgmt.monitor.v2019_06_01.models.ArmRoleReceiver]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'group_short_name': {'required': True, 'max_length': 12},
        'enabled': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'group_short_name': {'key': 'properties.groupShortName', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'email_receivers': {'key': 'properties.emailReceivers', 'type': '[EmailReceiver]'},
        'sms_receivers': {'key': 'properties.smsReceivers', 'type': '[SmsReceiver]'},
        'webhook_receivers': {'key': 'properties.webhookReceivers', 'type': '[WebhookReceiver]'},
        'itsm_receivers': {'key': 'properties.itsmReceivers', 'type': '[ItsmReceiver]'},
        'azure_app_push_receivers': {'key': 'properties.azureAppPushReceivers', 'type': '[AzureAppPushReceiver]'},
        'automation_runbook_receivers': {'key': 'properties.automationRunbookReceivers', 'type': '[AutomationRunbookReceiver]'},
        'voice_receivers': {'key': 'properties.voiceReceivers', 'type': '[VoiceReceiver]'},
        'logic_app_receivers': {'key': 'properties.logicAppReceivers', 'type': '[LogicAppReceiver]'},
        'azure_function_receivers': {'key': 'properties.azureFunctionReceivers', 'type': '[AzureFunctionReceiver]'},
        'arm_role_receivers': {'key': 'properties.armRoleReceivers', 'type': '[ArmRoleReceiver]'},
    }

    def __init__(self, *, location: str, group_short_name: str, tags=None, enabled: bool=True, email_receivers=None, sms_receivers=None, webhook_receivers=None, itsm_receivers=None, azure_app_push_receivers=None, automation_runbook_receivers=None, voice_receivers=None, logic_app_receivers=None, azure_function_receivers=None, arm_role_receivers=None, **kwargs) -> None:
        super(ActionGroupResource, self).__init__(location=location, tags=tags, **kwargs)
        self.group_short_name = group_short_name
        self.enabled = enabled
        self.email_receivers = email_receivers
        self.sms_receivers = sms_receivers
        self.webhook_receivers = webhook_receivers
        self.itsm_receivers = itsm_receivers
        self.azure_app_push_receivers = azure_app_push_receivers
        self.automation_runbook_receivers = automation_runbook_receivers
        self.voice_receivers = voice_receivers
        self.logic_app_receivers = logic_app_receivers
        self.azure_function_receivers = azure_function_receivers
        self.arm_role_receivers = arm_role_receivers
