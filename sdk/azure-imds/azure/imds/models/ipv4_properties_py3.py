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


class Ipv4Properties(Model):
    """This contains the IPv4 properties.

    :param private_ip_address: This is the private IP address assigned to the
     interface.
    :type private_ip_address: str
    :param public_ip_address: This is the public IP address assigned to the
     interface.
    :type public_ip_address: str
    """

    _attribute_map = {
        'private_ip_address': {'key': 'privateIpAddress', 'type': 'str'},
        'public_ip_address': {'key': 'publicIpAddress', 'type': 'str'},
    }

    def __init__(self, *, private_ip_address: str=None, public_ip_address: str=None, **kwargs) -> None:
        super(Ipv4Properties, self).__init__(**kwargs)
        self.private_ip_address = private_ip_address
        self.public_ip_address = public_ip_address
