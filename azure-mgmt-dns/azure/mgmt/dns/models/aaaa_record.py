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


class AaaaRecord(Model):
    """An AAAA record.

    :param ipv6_address: The IPv6 address of this AAAA record.
    :type ipv6_address: str
    """

    _attribute_map = {
        'ipv6_address': {'key': 'ipv6Address', 'type': 'str'},
    }

    def __init__(self, ipv6_address=None):
        self.ipv6_address = ipv6_address
