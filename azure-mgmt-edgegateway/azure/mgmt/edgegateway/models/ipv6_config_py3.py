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


class Ipv6Config(Model):
    """Details related to the IPv6 address configuration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar ip_address: The IPv6 address of the network adapter.
    :vartype ip_address: str
    :ivar prefix_length: The IPv6 prefix of the network adapter.
    :vartype prefix_length: int
    :ivar gateway: The IPv6 gateway of the network adapter.
    :vartype gateway: str
    """

    _validation = {
        'ip_address': {'readonly': True},
        'prefix_length': {'readonly': True},
        'gateway': {'readonly': True},
    }

    _attribute_map = {
        'ip_address': {'key': 'ipAddress', 'type': 'str'},
        'prefix_length': {'key': 'prefixLength', 'type': 'int'},
        'gateway': {'key': 'gateway', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Ipv6Config, self).__init__(**kwargs)
        self.ip_address = None
        self.prefix_length = None
        self.gateway = None
