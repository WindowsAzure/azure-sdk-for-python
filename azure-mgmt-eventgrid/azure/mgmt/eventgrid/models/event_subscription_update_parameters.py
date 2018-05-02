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


class EventSubscriptionUpdateParameters(Model):
    """Properties of the Event Subscription update.

    :param destination: Information about the destination where events have to
     be delivered for the event subscription.
    :type destination:
     ~azure.mgmt.eventgrid.models.EventSubscriptionDestination
    :param filter: Information about the filter for the event subscription.
    :type filter: ~azure.mgmt.eventgrid.models.EventSubscriptionFilter
    :param labels: List of user defined labels.
    :type labels: list[str]
    :param event_delivery_schema: The event delivery schema for the event
     subscription. Possible values include: 'EventGridSchema',
     'InputEventSchema', 'CloudEventV01Schema'. Default value:
     "EventGridSchema" .
    :type event_delivery_schema: str or
     ~azure.mgmt.eventgrid.models.EventDeliverySchema
    :param retry_policy: The retry policy for events. This can be used to
     configure maximum number of delivery attempts and time to live for events.
    :type retry_policy: ~azure.mgmt.eventgrid.models.RetryPolicy
    :param dead_letter_destination: The DeadLetter destination of the event
     subscription.
    :type dead_letter_destination:
     ~azure.mgmt.eventgrid.models.DeadLetterDestination
    """

    _attribute_map = {
        'destination': {'key': 'destination', 'type': 'EventSubscriptionDestination'},
        'filter': {'key': 'filter', 'type': 'EventSubscriptionFilter'},
        'labels': {'key': 'labels', 'type': '[str]'},
        'event_delivery_schema': {'key': 'eventDeliverySchema', 'type': 'str'},
        'retry_policy': {'key': 'retryPolicy', 'type': 'RetryPolicy'},
        'dead_letter_destination': {'key': 'deadLetterDestination', 'type': 'DeadLetterDestination'},
    }

    def __init__(self, destination=None, filter=None, labels=None, event_delivery_schema="EventGridSchema", retry_policy=None, dead_letter_destination=None):
        super(EventSubscriptionUpdateParameters, self).__init__()
        self.destination = destination
        self.filter = filter
        self.labels = labels
        self.event_delivery_schema = event_delivery_schema
        self.retry_policy = retry_policy
        self.dead_letter_destination = dead_letter_destination
