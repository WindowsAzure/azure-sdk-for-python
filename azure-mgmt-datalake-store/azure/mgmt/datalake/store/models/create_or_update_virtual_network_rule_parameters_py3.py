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


class CreateOrUpdateVirtualNetworkRuleParameters(Model):
    """The parameters used to create a new virtual network rule.

    All required parameters must be populated in order to send to Azure.

    :param subnet_id: Required. The resource identifier for the subnet.
    :type subnet_id: str
    """

    _validation = {
        'subnet_id': {'required': True},
    }

    _attribute_map = {
        'subnet_id': {'key': 'properties.subnetId', 'type': 'str'},
    }

    def __init__(self, *, subnet_id: str, **kwargs) -> None:
        super(CreateOrUpdateVirtualNetworkRuleParameters, self).__init__(**kwargs)
        self.subnet_id = subnet_id
