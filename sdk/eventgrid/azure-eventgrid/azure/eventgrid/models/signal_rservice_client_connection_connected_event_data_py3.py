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


class SignalRServiceClientConnectionConnectedEventData(Model):
    """Schema of the Data property of an EventGridEvent for a
    Microsoft.SignalRService.ClientConnectionConnected event.

    :param timestamp: The time at which the event occurred.
    :type timestamp: datetime
    :param hub: The hub of connected client connection.
    :type hub: str
    :param connection_id: The connection Id of connected client connection.
    :type connection_id: str
    :param user_id: The user Id of connected client connection.
    :type user_id: str
    """

    _attribute_map = {
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'hub': {'key': 'hub', 'type': 'str'},
        'connection_id': {'key': 'connectionId', 'type': 'str'},
        'user_id': {'key': 'userId', 'type': 'str'},
    }

    def __init__(self, *, timestamp=None, hub: str=None, connection_id: str=None, user_id: str=None, **kwargs) -> None:
        super(SignalRServiceClientConnectionConnectedEventData, self).__init__(**kwargs)
        self.timestamp = timestamp
        self.hub = hub
        self.connection_id = connection_id
        self.user_id = user_id
