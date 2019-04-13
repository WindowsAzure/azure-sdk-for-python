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


class Ipv4Config(Model):
    """Details related to the IPv4 address configuration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar ip_address: The IPv4 address of the network adapter.
    :vartype ip_address: str
    :ivar subnet: The IPv4 subnet of the network adapter.
    :vartype subnet: str
    :ivar gateway: The IPv4 gateway of the network adapter.
    :vartype gateway: str
    """

    _validation = {
        'ip_address': {'readonly': True},
        'subnet': {'readonly': True},
        'gateway': {'readonly': True},
    }

    _attribute_map = {
        'ip_address': {'key': 'ipAddress', 'type': 'str'},
        'subnet': {'key': 'subnet', 'type': 'str'},
        'gateway': {'key': 'gateway', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Ipv4Config, self).__init__(**kwargs)
        self.ip_address = None
        self.subnet = None
        self.gateway = None
