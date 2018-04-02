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

    :param action_group_id: the id of the action group to use.
    :type action_group_id: str
    :param webhook_properties:
    :type webhook_properties: dict[str, str]
    """

    _attribute_map = {
        'action_group_id': {'key': 'actionGroupId', 'type': 'str'},
        'webhook_properties': {'key': 'webhookProperties', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(Action, self).__init__(**kwargs)
        self.action_group_id = kwargs.get('action_group_id', None)
        self.webhook_properties = kwargs.get('webhook_properties', None)
