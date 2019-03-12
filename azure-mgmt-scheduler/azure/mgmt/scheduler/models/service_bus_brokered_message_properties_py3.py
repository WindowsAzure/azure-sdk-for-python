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


class ServiceBusBrokeredMessageProperties(Model):
    """ServiceBusBrokeredMessageProperties.

    :param content_type: Gets or sets the content type.
    :type content_type: str
    :param correlation_id: Gets or sets the correlation ID.
    :type correlation_id: str
    :param force_persistence: Gets or sets the force persistence.
    :type force_persistence: bool
    :param label: Gets or sets the label.
    :type label: str
    :param message_id: Gets or sets the message ID.
    :type message_id: str
    :param partition_key: Gets or sets the partition key.
    :type partition_key: str
    :param reply_to: Gets or sets the reply to.
    :type reply_to: str
    :param reply_to_session_id: Gets or sets the reply to session ID.
    :type reply_to_session_id: str
    :param scheduled_enqueue_time_utc: Gets or sets the scheduled enqueue time
     UTC.
    :type scheduled_enqueue_time_utc: datetime
    :param session_id: Gets or sets the session ID.
    :type session_id: str
    :param time_to_live: Gets or sets the time to live.
    :type time_to_live: timedelta
    :param to: Gets or sets the to.
    :type to: str
    :param via_partition_key: Gets or sets the via partition key.
    :type via_partition_key: str
    """

    _attribute_map = {
        'content_type': {'key': 'contentType', 'type': 'str'},
        'correlation_id': {'key': 'correlationId', 'type': 'str'},
        'force_persistence': {'key': 'forcePersistence', 'type': 'bool'},
        'label': {'key': 'label', 'type': 'str'},
        'message_id': {'key': 'messageId', 'type': 'str'},
        'partition_key': {'key': 'partitionKey', 'type': 'str'},
        'reply_to': {'key': 'replyTo', 'type': 'str'},
        'reply_to_session_id': {'key': 'replyToSessionId', 'type': 'str'},
        'scheduled_enqueue_time_utc': {'key': 'scheduledEnqueueTimeUtc', 'type': 'iso-8601'},
        'session_id': {'key': 'sessionId', 'type': 'str'},
        'time_to_live': {'key': 'timeToLive', 'type': 'duration'},
        'to': {'key': 'to', 'type': 'str'},
        'via_partition_key': {'key': 'viaPartitionKey', 'type': 'str'},
    }

    def __init__(self, *, content_type: str=None, correlation_id: str=None, force_persistence: bool=None, label: str=None, message_id: str=None, partition_key: str=None, reply_to: str=None, reply_to_session_id: str=None, scheduled_enqueue_time_utc=None, session_id: str=None, time_to_live=None, to: str=None, via_partition_key: str=None, **kwargs) -> None:
        super(ServiceBusBrokeredMessageProperties, self).__init__(**kwargs)
        self.content_type = content_type
        self.correlation_id = correlation_id
        self.force_persistence = force_persistence
        self.label = label
        self.message_id = message_id
        self.partition_key = partition_key
        self.reply_to = reply_to
        self.reply_to_session_id = reply_to_session_id
        self.scheduled_enqueue_time_utc = scheduled_enqueue_time_utc
        self.session_id = session_id
        self.time_to_live = time_to_live
        self.to = to
        self.via_partition_key = via_partition_key
