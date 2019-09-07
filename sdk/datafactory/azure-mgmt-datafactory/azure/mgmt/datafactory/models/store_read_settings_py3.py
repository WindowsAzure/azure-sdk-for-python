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


class StoreReadSettings(Model):
    """Connector read setting.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param type: Required. The read setting type.
    :type type: str
    :param max_concurrent_connections: The maximum concurrent connection count
     for the source data store. Type: integer (or Expression with resultType
     integer).
    :type max_concurrent_connections: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'type': {'key': 'type', 'type': 'str'},
        'max_concurrent_connections': {'key': 'maxConcurrentConnections', 'type': 'object'},
    }

    def __init__(self, *, type: str, additional_properties=None, max_concurrent_connections=None, **kwargs) -> None:
        super(StoreReadSettings, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.type = type
        self.max_concurrent_connections = max_concurrent_connections
