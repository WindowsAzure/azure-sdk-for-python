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


class InboundEnvironmentEndpoint(Model):
    """The IP Addresses and Ports that require inbound network access to and
    within the subnet of the App Service Environment.

    :param description: Short text describing the purpose of the network
     traffic.
    :type description: str
    :param endpoints: The IP addresses that network traffic will originate
     from in cidr notation.
    :type endpoints: list[str]
    :param ports: The ports that network traffic will arrive to the App
     Service Environment at.
    :type ports: list[str]
    """

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'endpoints': {'key': 'endpoints', 'type': '[str]'},
        'ports': {'key': 'ports', 'type': '[str]'},
    }

    def __init__(self, *, description: str=None, endpoints=None, ports=None, **kwargs) -> None:
        super(InboundEnvironmentEndpoint, self).__init__(**kwargs)
        self.description = description
        self.endpoints = endpoints
        self.ports = ports
