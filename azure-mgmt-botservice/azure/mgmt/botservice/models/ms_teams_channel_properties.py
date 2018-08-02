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


class MsTeamsChannelProperties(Model):
    """The parameters to provide for the Microsoft Teams channel.

    :param enable_calling: Enable calling for Microsoft Teams channel
    :type enable_calling: bool
    :param calling_web_hook: Webhook for Microsoft Teams channel calls
    :type calling_web_hook: str
    :param is_enabled: Whether this channel is enabled for the bot
    :type is_enabled: bool
    """

    _validation = {
        'is_enabled': {'required': True},
    }

    _attribute_map = {
        'enable_calling': {'key': 'enableCalling', 'type': 'bool'},
        'calling_web_hook': {'key': 'callingWebHook', 'type': 'str'},
        'is_enabled': {'key': 'isEnabled', 'type': 'bool'},
    }

    def __init__(self, is_enabled, enable_calling=None, calling_web_hook=None):
        self.enable_calling = enable_calling
        self.calling_web_hook = calling_web_hook
        self.is_enabled = is_enabled
