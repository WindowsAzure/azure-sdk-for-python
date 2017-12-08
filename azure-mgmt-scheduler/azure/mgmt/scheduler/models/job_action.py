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


class JobAction(Model):
    """JobAction.

    :param type: Gets or sets the job action type. Possible values include:
     'Http', 'Https', 'StorageQueue', 'ServiceBusQueue', 'ServiceBusTopic'
    :type type: str or ~azure.mgmt.scheduler.models.JobActionType
    :param request: Gets or sets the http requests.
    :type request: ~azure.mgmt.scheduler.models.HttpRequest
    :param queue_message: Gets or sets the storage queue message.
    :type queue_message: ~azure.mgmt.scheduler.models.StorageQueueMessage
    :param service_bus_queue_message: Gets or sets the service bus queue
     message.
    :type service_bus_queue_message:
     ~azure.mgmt.scheduler.models.ServiceBusQueueMessage
    :param service_bus_topic_message: Gets or sets the service bus topic
     message.
    :type service_bus_topic_message:
     ~azure.mgmt.scheduler.models.ServiceBusTopicMessage
    :param retry_policy: Gets or sets the retry policy.
    :type retry_policy: ~azure.mgmt.scheduler.models.RetryPolicy
    :param error_action: Gets or sets the error action.
    :type error_action: ~azure.mgmt.scheduler.models.JobErrorAction
    """

    _attribute_map = {
        'type': {'key': 'type', 'type': 'JobActionType'},
        'request': {'key': 'request', 'type': 'HttpRequest'},
        'queue_message': {'key': 'queueMessage', 'type': 'StorageQueueMessage'},
        'service_bus_queue_message': {'key': 'serviceBusQueueMessage', 'type': 'ServiceBusQueueMessage'},
        'service_bus_topic_message': {'key': 'serviceBusTopicMessage', 'type': 'ServiceBusTopicMessage'},
        'retry_policy': {'key': 'retryPolicy', 'type': 'RetryPolicy'},
        'error_action': {'key': 'errorAction', 'type': 'JobErrorAction'},
    }

    def __init__(self, type=None, request=None, queue_message=None, service_bus_queue_message=None, service_bus_topic_message=None, retry_policy=None, error_action=None):
        self.type = type
        self.request = request
        self.queue_message = queue_message
        self.service_bus_queue_message = service_bus_queue_message
        self.service_bus_topic_message = service_bus_topic_message
        self.retry_policy = retry_policy
        self.error_action = error_action
