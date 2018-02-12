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


class InboundEndpoint(Model):
    """An inbound endpoint on a compute node.

    :param name: The name of the endpoint.
    :type name: str
    :param protocol: The protocol of the endpoint. Possible values include:
     'tcp', 'udp'
    :type protocol: str or ~azure.batch.models.InboundEndpointProtocol
    :param public_ip_address: The public IP address of the compute node.
    :type public_ip_address: str
    :param public_fqdn: The public fully qualified domain name for the compute
     node.
    :type public_fqdn: str
    :param frontend_port: The public port number of the endpoint.
    :type frontend_port: int
    :param backend_port: The backend port number of the endpoint.
    :type backend_port: int
    """

    _validation = {
        'name': {'required': True},
        'protocol': {'required': True},
        'public_ip_address': {'required': True},
        'public_fqdn': {'required': True},
        'frontend_port': {'required': True},
        'backend_port': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'protocol': {'key': 'protocol', 'type': 'InboundEndpointProtocol'},
        'public_ip_address': {'key': 'publicIPAddress', 'type': 'str'},
        'public_fqdn': {'key': 'publicFQDN', 'type': 'str'},
        'frontend_port': {'key': 'frontendPort', 'type': 'int'},
        'backend_port': {'key': 'backendPort', 'type': 'int'},
    }

    def __init__(self, name, protocol, public_ip_address, public_fqdn, frontend_port, backend_port):
        super(InboundEndpoint, self).__init__()
        self.name = name
        self.protocol = protocol
        self.public_ip_address = public_ip_address
        self.public_fqdn = public_fqdn
        self.frontend_port = frontend_port
        self.backend_port = backend_port
