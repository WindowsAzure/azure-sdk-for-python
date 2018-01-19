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


class OriginUpdateParameters(Model):
    """Origin properties needed for origin creation or update.

    :param host_name: The address of the origin. Domain names, IPv4 addresses,
     and IPv6 addresses are supported.
    :type host_name: str
    :param http_port: The value of the HTTP port. Must be between 1 and 65535.
    :type http_port: int
    :param https_port: The value of the HTTPS port. Must be between 1 and
     65535.
    :type https_port: int
    """

    _validation = {
        'http_port': {'maximum': 65535, 'minimum': 1},
        'https_port': {'maximum': 65535, 'minimum': 1},
    }

    _attribute_map = {
        'host_name': {'key': 'properties.hostName', 'type': 'str'},
        'http_port': {'key': 'properties.httpPort', 'type': 'int'},
        'https_port': {'key': 'properties.httpsPort', 'type': 'int'},
    }

    def __init__(self, host_name=None, http_port=None, https_port=None):
        super(OriginUpdateParameters, self).__init__()
        self.host_name = host_name
        self.http_port = http_port
        self.https_port = https_port
