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


class IpSecurityRestriction(Model):
    """IP security restriction on an app.

    All required parameters must be populated in order to send to Azure.

    :param ip_address: Required. IP address the security restriction is valid
     for.
    :type ip_address: str
    :param subnet_mask: Subnet mask for the range of IP addresses the
     restriction is valid for.
    :type subnet_mask: str
    """

    _validation = {
        'ip_address': {'required': True},
    }

    _attribute_map = {
        'ip_address': {'key': 'ipAddress', 'type': 'str'},
        'subnet_mask': {'key': 'subnetMask', 'type': 'str'},
    }

    def __init__(self, *, ip_address: str, subnet_mask: str=None, **kwargs) -> None:
        super(IpSecurityRestriction, self).__init__(**kwargs)
        self.ip_address = ip_address
        self.subnet_mask = subnet_mask
