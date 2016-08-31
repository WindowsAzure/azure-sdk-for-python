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


class JobErrorAction(Model):
    """JobErrorAction.

    :param type: Gets or sets the job error action type. Possible values
     include: 'Http', 'Https', 'StorageQueue', 'ServiceBusQueue',
     'ServiceBusTopic'
    :type type: str or :class:`JobActionType
     <azure.mgmt.scheduler.models.JobActionType>`
    :param request: Gets or sets the http requests.
    :type request: :class:`HttpRequest
     <azure.mgmt.scheduler.models.HttpRequest>`
    :param queue_message: Gets or sets the storage queue message.
    :type queue_message: :class:`StorageQueueMessage
     <azure.mgmt.scheduler.models.StorageQueueMessage>`
    :param service_bus_queue_message: Gets or sets the service bus queue
     message.
    :type service_bus_queue_message: :class:`ServiceBusQueueMessage
     <azure.mgmt.scheduler.models.ServiceBusQueueMessage>`
    :param service_bus_topic_message: Gets or sets the service bus topic
     message.
    :type service_bus_topic_message: :class:`ServiceBusTopicMessage
     <azure.mgmt.scheduler.models.ServiceBusTopicMessage>`
    :param retry_policy: Gets or sets the retry policy.
    :type retry_policy: :class:`RetryPolicy
     <azure.mgmt.scheduler.models.RetryPolicy>`
    """ 

    _attribute_map = {
        'type': {'key': 'type', 'type': 'JobActionType'},
        'request': {'key': 'request', 'type': 'HttpRequest'},
        'queue_message': {'key': 'queueMessage', 'type': 'StorageQueueMessage'},
        'service_bus_queue_message': {'key': 'serviceBusQueueMessage', 'type': 'ServiceBusQueueMessage'},
        'service_bus_topic_message': {'key': 'serviceBusTopicMessage', 'type': 'ServiceBusTopicMessage'},
        'retry_policy': {'key': 'retryPolicy', 'type': 'RetryPolicy'},
    }

    def __init__(self, type=None, request=None, queue_message=None, service_bus_queue_message=None, service_bus_topic_message=None, retry_policy=None):
        self.type = type
        self.request = request
        self.queue_message = queue_message
        self.service_bus_queue_message = service_bus_queue_message
        self.service_bus_topic_message = service_bus_topic_message
        self.retry_policy = retry_policy
