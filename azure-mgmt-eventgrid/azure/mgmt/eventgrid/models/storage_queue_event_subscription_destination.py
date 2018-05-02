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


class StorageQueueEventSubscriptionDestination(EventSubscriptionDestination):
    """Information about the storage queue destination for an event subscription.

    :param endpoint_type: Constant filled by server.
    :type endpoint_type: str
    :param resource_id: The Azure Resource ID of the storage account that
     contains the queue that is the destination of an event subscription.
    :type resource_id: str
    :param queue_name: The name of the Storage queue under a storage account
     that is the destination of an event subscription.
    :type queue_name: str
    """

    _validation = {
        'endpoint_type': {'required': True},
    }

    _attribute_map = {
        'endpoint_type': {'key': 'endpointType', 'type': 'str'},
        'resource_id': {'key': 'properties.resourceId', 'type': 'str'},
        'queue_name': {'key': 'properties.queueName', 'type': 'str'},
    }

    def __init__(self, resource_id=None, queue_name=None):
        super(StorageQueueEventSubscriptionDestination, self).__init__()
        self.resource_id = resource_id
        self.queue_name = queue_name
        self.endpoint_type = 'StorageQueue'
