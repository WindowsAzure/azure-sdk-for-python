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


class ActivityLogAlertActionGroup(Model):
    """A pointer to an Azure Action Group.

    All required parameters must be populated in order to send to Azure.

    :param action_group_id: Required. The resourceId of the action group. This
     cannot be null or empty.
    :type action_group_id: str
    :param webhook_properties: the dictionary of custom properties to include
     with the post operation. These data are appended to the webhook payload.
    :type webhook_properties: dict[str, str]
    """

    _validation = {
        'action_group_id': {'required': True},
    }

    _attribute_map = {
        'action_group_id': {'key': 'actionGroupId', 'type': 'str'},
        'webhook_properties': {'key': 'webhookProperties', 'type': '{str}'},
    }

    def __init__(self, *, action_group_id: str, webhook_properties=None, **kwargs) -> None:
        super(ActivityLogAlertActionGroup, self).__init__(**kwargs)
        self.action_group_id = action_group_id
        self.webhook_properties = webhook_properties
