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


class CidrIpAddress(Model):
    """CIDR Ip address.

    :param base_ip_address: Ip adress itself.
    :type base_ip_address: str
    :param prefix_length: The length of the prefix of the ip address.
    :type prefix_length: int
    """

    _attribute_map = {
        'base_ip_address': {'key': 'baseIpAddress', 'type': 'str'},
        'prefix_length': {'key': 'prefixLength', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(CidrIpAddress, self).__init__(**kwargs)
        self.base_ip_address = kwargs.get('base_ip_address', None)
        self.prefix_length = kwargs.get('prefix_length', None)
