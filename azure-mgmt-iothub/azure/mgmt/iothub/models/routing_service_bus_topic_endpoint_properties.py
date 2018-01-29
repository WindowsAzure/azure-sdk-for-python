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


class RoutingServiceBusTopicEndpointProperties(Model):
    """The properties related to service bus topic endpoint types.

    :param connection_string: The connection string of the service bus topic
     endpoint.
    :type connection_string: str
    :param name: The name that identifies this endpoint. The name can only
     include alphanumeric characters, periods, underscores, hyphens and has a
     maximum length of 64 characters. The following names are reserved:
     events, operationsMonitoringEvents, fileNotifications, $default. Endpoint
     names must be unique across endpoint types.  The name need not be the same
     as the actual topic name.
    :type name: str
    :param subscription_id: The subscription identifier of the service bus
     topic endpoint.
    :type subscription_id: str
    :param resource_group: The name of the resource group of the service bus
     topic endpoint.
    :type resource_group: str
    """

    _validation = {
        'connection_string': {'required': True},
        'name': {'required': True, 'pattern': r'^[A-Za-z0-9-._]{1,64}$'},
    }

    _attribute_map = {
        'connection_string': {'key': 'connectionString', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'resource_group': {'key': 'resourceGroup', 'type': 'str'},
    }

    def __init__(self, connection_string, name, subscription_id=None, resource_group=None):
        super(RoutingServiceBusTopicEndpointProperties, self).__init__()
        self.connection_string = connection_string
        self.name = name
        self.subscription_id = subscription_id
        self.resource_group = resource_group
