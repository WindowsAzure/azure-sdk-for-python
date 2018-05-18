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


class UpdateVirtualNetworkRuleParameters(Model):
    """The parameters used to update a virtual network rule.

    :param subnet_id: The resource identifier for the subnet.
    :type subnet_id: str
    """

    _attribute_map = {
        'subnet_id': {'key': 'properties.subnetId', 'type': 'str'},
    }

    def __init__(self, *, subnet_id: str=None, **kwargs) -> None:
        super(UpdateVirtualNetworkRuleParameters, self).__init__(**kwargs)
        self.subnet_id = subnet_id
