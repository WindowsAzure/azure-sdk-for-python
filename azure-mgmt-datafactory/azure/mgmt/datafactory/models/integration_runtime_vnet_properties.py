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


class IntegrationRuntimeVNetProperties(Model):
    """VNet properties for managed integration runtime.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param v_net_id: The ID of the VNet that this integration runtime will
     join.
    :type v_net_id: str
    :param subnet: The name of the subnet this integration runtime will join.
    :type subnet: str
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'v_net_id': {'key': 'vNetId', 'type': 'str'},
        'subnet': {'key': 'subnet', 'type': 'str'},
    }

    def __init__(self, additional_properties=None, v_net_id=None, subnet=None):
        self.additional_properties = additional_properties
        self.v_net_id = v_net_id
        self.subnet = subnet
