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


class PortFragment(Model):
    """Properties of a network port.

    :param transport_protocol: Protocol type of the port. Possible values
     include: 'Tcp', 'Udp'
    :type transport_protocol: str or
     ~azure.mgmt.devtestlabs.models.TransportProtocol
    :param backend_port: Backend port of the target virtual machine.
    :type backend_port: int
    """

    _attribute_map = {
        'transport_protocol': {'key': 'transportProtocol', 'type': 'str'},
        'backend_port': {'key': 'backendPort', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(PortFragment, self).__init__(**kwargs)
        self.transport_protocol = kwargs.get('transport_protocol', None)
        self.backend_port = kwargs.get('backend_port', None)
