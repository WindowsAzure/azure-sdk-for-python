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


class Message(Model):
    """Supplementary contextual messages during a rollout.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar time_stamp: Time in UTC this message was provided.
    :vartype time_stamp: datetime
    :ivar message: The actual message text.
    :vartype message: str
    """

    _validation = {
        'time_stamp': {'readonly': True},
        'message': {'readonly': True},
    }

    _attribute_map = {
        'time_stamp': {'key': 'timeStamp', 'type': 'iso-8601'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Message, self).__init__(**kwargs)
        self.time_stamp = None
        self.message = None
