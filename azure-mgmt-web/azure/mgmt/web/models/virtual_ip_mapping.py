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


class VirtualIPMapping(Model):
    """Class that represents a VIP mapping.

    :param virtual_ip: Virtual IP address
    :type virtual_ip: str
    :param internal_http_port: Internal HTTP port
    :type internal_http_port: int
    :param internal_https_port: Internal HTTPS port
    :type internal_https_port: int
    :param in_use: Is VIP mapping in use
    :type in_use: bool
    """

    _attribute_map = {
        'virtual_ip': {'key': 'virtualIP', 'type': 'str'},
        'internal_http_port': {'key': 'internalHttpPort', 'type': 'int'},
        'internal_https_port': {'key': 'internalHttpsPort', 'type': 'int'},
        'in_use': {'key': 'inUse', 'type': 'bool'},
    }

    def __init__(self, virtual_ip=None, internal_http_port=None, internal_https_port=None, in_use=None):
        self.virtual_ip = virtual_ip
        self.internal_http_port = internal_http_port
        self.internal_https_port = internal_https_port
        self.in_use = in_use
