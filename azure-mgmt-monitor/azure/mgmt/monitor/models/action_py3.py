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


class Action(Model):
    """An alert action.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AlertingAction

    All required parameters must be populated in order to send to Azure.

    :param action_group_id: the id of the action group to use.
    :type action_group_id: str
    :param webhook_properties:
    :type webhook_properties: dict[str, str]
    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'action_group_id': {'key': 'actionGroupId', 'type': 'str'},
        'webhook_properties': {'key': 'webhookProperties', 'type': '{str}'},
        'odatatype': {'key': 'odata\\.type', 'type': 'str'},
    }

    _subtype_map = {
        'odatatype': {'Microsoft.WindowsAzure.Management.Monitoring.Alerts.Models.Microsoft.AppInsights.Nexus.DataContracts.Resources.ScheduledQueryRules.AlertingAction': 'AlertingAction'}
    }

    def __init__(self, *, action_group_id: str=None, webhook_properties=None, **kwargs) -> None:
        super(Action, self).__init__(**kwargs)
        self.action_group_id = action_group_id
        self.webhook_properties = webhook_properties
        self.odatatype = None
