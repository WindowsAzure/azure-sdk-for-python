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
    :param expiration_time_utc: Information about the expiration time for the
     event subscription.
    :type expiration_time_utc: datetime
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
        'expiration_time_utc': {'key': 'expirationTimeUtc', 'type': 'iso-8601'},
        'retry_policy': {'key': 'retryPolicy', 'type': 'RetryPolicy'},
        'dead_letter_destination': {'key': 'deadLetterDestination', 'type': 'DeadLetterDestination'},
    }

    def __init__(self, **kwargs):
        super(EventSubscriptionUpdateParameters, self).__init__(**kwargs)
        self.destination = kwargs.get('destination', None)
        self.filter = kwargs.get('filter', None)
        self.labels = kwargs.get('labels', None)
        self.expiration_time_utc = kwargs.get('expiration_time_utc', None)
        self.retry_policy = kwargs.get('retry_policy', None)
        self.dead_letter_destination = kwargs.get('dead_letter_destination', None)
