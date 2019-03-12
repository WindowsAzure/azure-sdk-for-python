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


class ProtocolConfiguration(Model):
    """Configuration of the protocol.

    :param http_configuration:
    :type http_configuration:
     ~azure.mgmt.network.v2018_06_01.models.HTTPConfiguration
    """

    _attribute_map = {
        'http_configuration': {'key': 'HTTPConfiguration', 'type': 'HTTPConfiguration'},
    }

    def __init__(self, *, http_configuration=None, **kwargs) -> None:
        super(ProtocolConfiguration, self).__init__(**kwargs)
        self.http_configuration = http_configuration
