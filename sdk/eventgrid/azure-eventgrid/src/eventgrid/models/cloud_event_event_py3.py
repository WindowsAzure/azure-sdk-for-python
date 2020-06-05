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


class CloudEventEvent(Model):
    """Properties of an event published to an Event Grid topic using the
    CloudEvent 1.0 Schema.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. An identifier for the event. The combination of id
     and source must be unique for each distinct event.
    :type id: str
    :param source: Required. Identifies the context in which an event
     happened. The combination of id and source must be unique for each
     distinct event.
    :type source: str
    :param data: Event data specific to the event type.
    :type data: object
    :param type: Required. Type of event related to the originating
     occurrence.
    :type type: str
    :param time: The time (in UTC) the event was generated, in RFC3339 format.
    :type time: datetime
    :param specversion: Required. The version of the CloudEvents specification
     which the event uses.
    :type specversion: str
    :param dataschema: Identifies the schema that data adheres to.
    :type dataschema: str
    :param datacontenttype: Content type of data value.
    :type datacontenttype: str
    :param subject: This describes the subject of the event in the context of
     the event producer (identified by source).
    :type subject: str
    """

    _validation = {
        'id': {'required': True},
        'source': {'required': True},
        'type': {'required': True},
        'specversion': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'source': {'key': 'source', 'type': 'str'},
        'data': {'key': 'data', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'time': {'key': 'time', 'type': 'iso-8601'},
        'specversion': {'key': 'specversion', 'type': 'str'},
        'dataschema': {'key': 'dataschema', 'type': 'str'},
        'datacontenttype': {'key': 'datacontenttype', 'type': 'str'},
        'subject': {'key': 'subject', 'type': 'str'},
    }

    def __init__(self, *, id: str, source: str, type: str, specversion: str, data=None, time=None, dataschema: str=None, datacontenttype: str=None, subject: str=None, **kwargs) -> None:
        super(CloudEventEvent, self).__init__(**kwargs)
        self.id = id
        self.source = source
        self.data = data
        self.type = type
        self.time = time
        self.specversion = specversion
        self.dataschema = dataschema
        self.datacontenttype = datacontenttype
        self.subject = subject
