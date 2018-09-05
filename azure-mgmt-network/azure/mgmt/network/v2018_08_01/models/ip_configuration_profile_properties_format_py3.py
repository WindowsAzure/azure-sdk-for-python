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


class IPConfigurationProfilePropertiesFormat(Model):
    """IP configruation profile properties.

    :param subnet: The reference of the subnet resource to create a
     contatainer network interface ip configruation.
    :type subnet: ~azure.mgmt.network.v2018_08_01.models.Subnet
    """

    _attribute_map = {
        'subnet': {'key': 'subnet', 'type': 'Subnet'},
    }

    def __init__(self, *, subnet=None, **kwargs) -> None:
        super(IPConfigurationProfilePropertiesFormat, self).__init__(**kwargs)
        self.subnet = subnet
