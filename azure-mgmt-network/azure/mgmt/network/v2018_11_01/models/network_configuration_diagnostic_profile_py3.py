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


class NetworkConfigurationDiagnosticProfile(Model):
    """Parameters to compare with network configuration.

    All required parameters must be populated in order to send to Azure.

    :param direction: Required. The direction of the traffic. Accepted values
     are 'Inbound' and 'Outbound'. Possible values include: 'Inbound',
     'Outbound'
    :type direction: str or ~azure.mgmt.network.v2018_11_01.models.Direction
    :param protocol: Required. Protocol to be verified on. Accepted values are
     '*', TCP, UDP.
    :type protocol: str
    :param source: Required. Traffic source. Accepted values are '*', IP
     Address/CIDR, Service Tag.
    :type source: str
    :param destination: Required. Traffic destination. Accepted values are:
     '*', IP Address/CIDR, Service Tag.
    :type destination: str
    :param destination_port: Required. Traffice destination port. Accepted
     values are '*', port (for example, 3389) and port range (for example,
     80-100).
    :type destination_port: str
    """

    _validation = {
        'direction': {'required': True},
        'protocol': {'required': True},
        'source': {'required': True},
        'destination': {'required': True},
        'destination_port': {'required': True},
    }

    _attribute_map = {
        'direction': {'key': 'direction', 'type': 'str'},
        'protocol': {'key': 'protocol', 'type': 'str'},
        'source': {'key': 'source', 'type': 'str'},
        'destination': {'key': 'destination', 'type': 'str'},
        'destination_port': {'key': 'destinationPort', 'type': 'str'},
    }

    def __init__(self, *, direction, protocol: str, source: str, destination: str, destination_port: str, **kwargs) -> None:
        super(NetworkConfigurationDiagnosticProfile, self).__init__(**kwargs)
        self.direction = direction
        self.protocol = protocol
        self.source = source
        self.destination = destination
        self.destination_port = destination_port
