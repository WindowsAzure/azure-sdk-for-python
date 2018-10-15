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


class SyncMigrationDatabaseErrorEvent(Model):
    """Database migration errors for online migration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar timestamp_string: String value of timestamp.
    :vartype timestamp_string: str
    :ivar event_type_string: Event type.
    :vartype event_type_string: str
    :ivar event_text: Event text.
    :vartype event_text: str
    """

    _validation = {
        'timestamp_string': {'readonly': True},
        'event_type_string': {'readonly': True},
        'event_text': {'readonly': True},
    }

    _attribute_map = {
        'timestamp_string': {'key': 'timestampString', 'type': 'str'},
        'event_type_string': {'key': 'eventTypeString', 'type': 'str'},
        'event_text': {'key': 'eventText', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(SyncMigrationDatabaseErrorEvent, self).__init__(**kwargs)
        self.timestamp_string = None
        self.event_type_string = None
        self.event_text = None
