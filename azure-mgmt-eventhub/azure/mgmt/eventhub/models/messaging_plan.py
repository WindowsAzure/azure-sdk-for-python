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

from .tracked_resource import TrackedResource


class MessagingPlan(TrackedResource):
    """Messaging Plan for the namespace.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :ivar sku: Sku type
    :vartype sku: int
    :ivar selected_event_hub_unit: Selected event hub unit
    :vartype selected_event_hub_unit: int
    :ivar updated_at: The exact time the messaging plan was updated.
    :vartype updated_at: datetime
    :ivar revision: revision number
    :vartype revision: long
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'sku': {'readonly': True},
        'selected_event_hub_unit': {'readonly': True},
        'updated_at': {'readonly': True},
        'revision': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'properties.sku', 'type': 'int'},
        'selected_event_hub_unit': {'key': 'properties.selectedEventHubUnit', 'type': 'int'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'revision': {'key': 'properties.revision', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(MessagingPlan, self).__init__(**kwargs)
        self.sku = None
        self.selected_event_hub_unit = None
        self.updated_at = None
        self.revision = None
