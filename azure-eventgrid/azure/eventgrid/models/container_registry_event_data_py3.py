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

from .event_grid_event_data_py3 import EventGridEventData


class ContainerRegistryEventData(EventGridEventData):
    """The content of the event request message.

    :param id: The event ID.
    :type id: str
    :param timestamp: The time at which the event occurred.
    :type timestamp: datetime
    :param action: The action that encompasses the provided event.
    :type action: str
    :param target: The target of the event.
    :type target: ~azure.eventgrid.models.ContainerRegistryEventTarget
    :param request: The request that generated the event.
    :type request: ~azure.eventgrid.models.ContainerRegistryEventRequest
    :param actor: The agent that initiated the event. For most situations,
     this could be from the authorization context of the request.
    :type actor: ~azure.eventgrid.models.ContainerRegistryEventActor
    :param source: The registry node that generated the event. Put
     differently, while the actor initiates the event, the source generates it.
    :type source: ~azure.eventgrid.models.ContainerRegistryEventSource
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'action': {'key': 'action', 'type': 'str'},
        'target': {'key': 'target', 'type': 'ContainerRegistryEventTarget'},
        'request': {'key': 'request', 'type': 'ContainerRegistryEventRequest'},
        'actor': {'key': 'actor', 'type': 'ContainerRegistryEventActor'},
        'source': {'key': 'source', 'type': 'ContainerRegistryEventSource'},
    }

    def __init__(self, *, id: str=None, timestamp=None, action: str=None, target=None, request=None, actor=None, source=None, **kwargs) -> None:
        super(ContainerRegistryEventData, self).__init__(**kwargs)
        self.id = id
        self.timestamp = timestamp
        self.action = action
        self.target = target
        self.request = request
        self.actor = actor
        self.source = source
