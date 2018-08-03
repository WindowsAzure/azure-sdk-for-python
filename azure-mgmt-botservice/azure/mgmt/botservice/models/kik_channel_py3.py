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

from .channel_py3 import Channel


class KikChannel(Channel):
    """Kik channel definition.

    All required parameters must be populated in order to send to Azure.

    :param channel_name: Required. Constant filled by server.
    :type channel_name: str
    :param properties: The set of properties specific to Kik channel resource
    :type properties: ~azure.mgmt.botservice.models.KikChannelProperties
    """

    _validation = {
        'channel_name': {'required': True},
    }

    _attribute_map = {
        'channel_name': {'key': 'channelName', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'KikChannelProperties'},
    }

    def __init__(self, *, properties=None, **kwargs) -> None:
        super(KikChannel, self).__init__(**kwargs)
        self.properties = properties
        self.channel_name = 'KikChannel'
