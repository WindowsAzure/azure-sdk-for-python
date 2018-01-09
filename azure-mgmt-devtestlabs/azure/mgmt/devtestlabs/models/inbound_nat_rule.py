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


class InboundNatRule(Model):
    """A rule for NAT - exposing a VM's port (backendPort) on the public IP
    address using a load balancer.

    :param transport_protocol: The transport protocol for the endpoint.
     Possible values include: 'Tcp', 'Udp'
    :type transport_protocol: str or
     ~azure.mgmt.devtestlabs.models.TransportProtocol
    :param frontend_port: The external endpoint port of the inbound
     connection. Possible values range between 1 and 65535, inclusive. If
     unspecified, a value will be allocated automatically.
    :type frontend_port: int
    :param backend_port: The port to which the external traffic will be
     redirected.
    :type backend_port: int
    """

    _attribute_map = {
        'transport_protocol': {'key': 'transportProtocol', 'type': 'str'},
        'frontend_port': {'key': 'frontendPort', 'type': 'int'},
        'backend_port': {'key': 'backendPort', 'type': 'int'},
    }

    def __init__(self, transport_protocol=None, frontend_port=None, backend_port=None):
        super(InboundNatRule, self).__init__()
        self.transport_protocol = transport_protocol
        self.frontend_port = frontend_port
        self.backend_port = backend_port
