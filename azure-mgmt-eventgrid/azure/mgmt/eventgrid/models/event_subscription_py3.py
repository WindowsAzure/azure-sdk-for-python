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

from .resource import Resource


class EventSubscription(Resource):
    """Event Subscription.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified identifier of the resource
    :vartype id: str
    :ivar name: Name of the resource
    :vartype name: str
    :ivar type: Type of the resource
    :vartype type: str
    :ivar topic: Name of the topic of the event subscription.
    :vartype topic: str
    :ivar provisioning_state: Provisioning state of the event subscription.
     Possible values include: 'Creating', 'Updating', 'Deleting', 'Succeeded',
     'Canceled', 'Failed'
    :vartype provisioning_state: str or
     ~azure.mgmt.eventgrid.models.EventSubscriptionProvisioningState
    :param destination: Information about the destination where events have to
     be delivered for the event subscription.
    :type destination:
     ~azure.mgmt.eventgrid.models.EventSubscriptionDestination
    :param filter: Information about the filter for the event subscription.
    :type filter: ~azure.mgmt.eventgrid.models.EventSubscriptionFilter
    :param labels: List of user defined labels.
    :type labels: list[str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'topic': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'topic': {'key': 'properties.topic', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'destination': {'key': 'properties.destination', 'type': 'EventSubscriptionDestination'},
        'filter': {'key': 'properties.filter', 'type': 'EventSubscriptionFilter'},
        'labels': {'key': 'properties.labels', 'type': '[str]'},
    }

    def __init__(self, *, destination=None, filter=None, labels=None, **kwargs) -> None:
        super(EventSubscription, self).__init__(**kwargs)
        self.topic = None
        self.provisioning_state = None
        self.destination = destination
        self.filter = filter
        self.labels = labels
