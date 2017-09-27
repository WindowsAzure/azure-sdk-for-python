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


class FallbackRouteProperties(Model):
    """The properties of the fallback route. IoT Hub uses these properties when it
    routes messages to the fallback endpoint.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar source: The source to which the routing rule is to be applied to.
     For example, DeviceMessages. Default value: "DeviceMessages" .
    :vartype source: str
    :param condition: The condition which is evaluated in order to apply the
     fallback route. If the condition is not provided it will evaluate to true
     by default. For grammar, See:
     https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-query-language
    :type condition: str
    :param endpoint_names: The list of endpoints to which the messages that
     satisfy the condition are routed to. Currently only 1 endpoint is allowed.
    :type endpoint_names: list of str
    :param is_enabled: Used to specify whether the fallback route is enabled.
    :type is_enabled: bool
    """

    _validation = {
        'source': {'required': True, 'constant': True},
        'endpoint_names': {'required': True, 'max_items': 1, 'min_items': 1},
        'is_enabled': {'required': True},
    }

    _attribute_map = {
        'source': {'key': 'source', 'type': 'str'},
        'condition': {'key': 'condition', 'type': 'str'},
        'endpoint_names': {'key': 'endpointNames', 'type': '[str]'},
        'is_enabled': {'key': 'isEnabled', 'type': 'bool'},
    }

    source = "DeviceMessages"

    def __init__(self, endpoint_names, is_enabled, condition=None):
        self.condition = condition
        self.endpoint_names = endpoint_names
        self.is_enabled = is_enabled
