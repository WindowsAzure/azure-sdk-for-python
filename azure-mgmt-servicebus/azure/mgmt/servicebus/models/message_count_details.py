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


class MessageCountDetails(Model):
    """Message Count Details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar active_message_count: Number of active messages in the queue, topic,
     or subscription.
    :vartype active_message_count: long
    :ivar dead_letter_message_count: Number of messages that are dead
     lettered.
    :vartype dead_letter_message_count: long
    :ivar scheduled_message_count: Number of scheduled messages.
    :vartype scheduled_message_count: long
    :ivar transfer_message_count: Number of messages transferred to another
     queue, topic, or subscription.
    :vartype transfer_message_count: long
    :ivar transfer_dead_letter_message_count: Number of messages transferred
     into dead letters.
    :vartype transfer_dead_letter_message_count: long
    """

    _validation = {
        'active_message_count': {'readonly': True},
        'dead_letter_message_count': {'readonly': True},
        'scheduled_message_count': {'readonly': True},
        'transfer_message_count': {'readonly': True},
        'transfer_dead_letter_message_count': {'readonly': True},
    }

    _attribute_map = {
        'active_message_count': {'key': 'activeMessageCount', 'type': 'long'},
        'dead_letter_message_count': {'key': 'deadLetterMessageCount', 'type': 'long'},
        'scheduled_message_count': {'key': 'scheduledMessageCount', 'type': 'long'},
        'transfer_message_count': {'key': 'transferMessageCount', 'type': 'long'},
        'transfer_dead_letter_message_count': {'key': 'transferDeadLetterMessageCount', 'type': 'long'},
    }

    def __init__(self):
        super(MessageCountDetails, self).__init__()
        self.active_message_count = None
        self.dead_letter_message_count = None
        self.scheduled_message_count = None
        self.transfer_message_count = None
        self.transfer_dead_letter_message_count = None
