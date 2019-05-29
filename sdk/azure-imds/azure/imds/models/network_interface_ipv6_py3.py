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


class NetworkInterfaceIpv6(Model):
    """This contains the IPv6 address.

    :param ip_address: This is the IP address
    :type ip_address: list[~azure.imds.models.Ipv6Properties]
    """

    _attribute_map = {
        'ip_address': {'key': 'ipAddress', 'type': '[Ipv6Properties]'},
    }

    def __init__(self, *, ip_address=None, **kwargs) -> None:
        super(NetworkInterfaceIpv6, self).__init__(**kwargs)
        self.ip_address = ip_address
