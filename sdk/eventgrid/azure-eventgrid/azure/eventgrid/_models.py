# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
# pylint:disable=protected-access
from typing import Union, Any, Dict
import datetime as dt
import uuid
import json
import six
from msrest.serialization import UTC
from ._generated.models import EventGridEvent as InternalEventGridEvent


class EventGridEvent(InternalEventGridEvent):
    """Properties of an event published to an Event Grid topic using the EventGrid Schema.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :param subject: Required. A resource path relative to the topic path.
    :type subject: str
    :param event_type: Required. The type of the event that occurred.
    :type event_type: str
    :param data: Required. Event data specific to the event type.
    :type data: object
    :param data_version: Required. The schema version of the data object.
     If not provided, will be stamped with an empty value.
    :type data_version: str
    :keyword topic: Optional. The resource path of the event source. If not provided, Event Grid will
     stamp onto the event.
    :type topic: str
    :keyword metadata_version: Optional. The schema version of the event metadata. If provided,
     must match Event Grid Schema exactly. If not provided, EventGrid will stamp onto event.
    :type metadata_version: str
    :keyword id: Optional. An identifier for the event. In not provided, a random UUID will be generated and used.
    :type id: Optional[str]
    :keyword event_time: Optional.The time (in UTC) of the event. If not provided,
     it will be the time (in UTC) the event was generated.
    :type event_time: Optional[~datetime.datetime]
    :ivar subject: A resource path relative to the topic path.
    :vartype subject: str
    :ivar event_type: The type of the event that occurred.
    :vartype event_type: str
    :ivar data: Event data specific to the event type.
    :vartype data: object
    :ivar data_version: The schema version of the data object.
     If not provided, will be stamped with an empty value.
    :vartype data_version: str
    :ivar topic: The resource path of the event source. If not provided, Event Grid will stamp onto the event.
    :vartype topic: str
    :ivar metadata_version: The schema version of the event metadata. If provided, must match Event Grid Schema exactly.
     If not provided, EventGrid will stamp onto event.
    :vartype metadata_version: str
    :ivar id: An identifier for the event. In not provided, a random UUID will be generated and used.
    :vartype id: Optional[str]
    :ivar event_time: The time (in UTC) of the event. If not provided,
     it will be the time (in UTC) the event was generated.
    :vartype event_time: Optional[~datetime.datetime]
    """

    _validation = {
        'id': {'required': True},
        'subject': {'required': True},
        'data': {'required': True},
        'event_type': {'required': True},
        'event_time': {'required': True},
        'metadata_version': {'readonly': True},
        'data_version': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'topic': {'key': 'topic', 'type': 'str'},
        'subject': {'key': 'subject', 'type': 'str'},
        'data': {'key': 'data', 'type': 'object'},
        'event_type': {'key': 'eventType', 'type': 'str'},
        'event_time': {'key': 'eventTime', 'type': 'iso-8601'},
        'metadata_version': {'key': 'metadataVersion', 'type': 'str'},
        'data_version': {'key': 'dataVersion', 'type': 'str'},
    }

    def __init__(self, subject, event_type, data, data_version, **kwargs):
        # type: (str, str, object, str, Any) -> None
        kwargs.setdefault('id', uuid.uuid4())
        kwargs.setdefault('subject', subject)
        kwargs.setdefault("event_type", event_type)
        kwargs.setdefault('event_time', dt.datetime.now(UTC()).isoformat())
        kwargs.setdefault('data', data)
        kwargs.setdefault('data_version', data_version)

        super(EventGridEvent, self).__init__(**kwargs)

    @classmethod
    def from_dict(cls, event, **kwargs):
        # type: (Dict, Any) -> EventGridEvent
        """
        Returns the deserialized EventGridEvent object when a dict is provided.

        :param event: The dict representation of the event which needs to be deserialized.
        :type event: dict

        :rtype: EventGridEvent
        """
        return cls(
        id=event.get("id", None),
        subject=event.get("subject", None),
        topic=event.get("topic", None),
        data_version=event.get("dataVersion", None),
        data=event.get("data", None),
        event_time=event.get("eventTime", None),
        event_type=event.get("eventType", None),
        metadata_version=event.get("metadataVersion", None),
        **kwargs
        )
