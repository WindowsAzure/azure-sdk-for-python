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

from .event_subscription_destination import EventSubscriptionDestination


class EventHubEventSubscriptionDestination(EventSubscriptionDestination):
    """Information about the event hub destination for an event subscription.

    :param endpoint_type: Constant filled by server.
    :type endpoint_type: str
    :param resource_id: The Azure Resource Id that represents the endpoint of
     an Event Hub destination of an event subscription.
    :type resource_id: str
    """

    _validation = {
        'endpoint_type': {'required': True},
    }

    _attribute_map = {
        'endpoint_type': {'key': 'endpointType', 'type': 'str'},
        'resource_id': {'key': 'properties.resourceId', 'type': 'str'},
    }

    def __init__(self, resource_id=None):
        super(EventHubEventSubscriptionDestination, self).__init__()
        self.resource_id = resource_id
        self.endpoint_type = 'EventHub'
