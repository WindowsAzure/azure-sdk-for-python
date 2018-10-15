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


class VirtualMachineScaleSetUpdateNetworkProfile(Model):
    """Describes a virtual machine scale set network profile.

    :param network_interface_configurations: The list of network
     configurations.
    :type network_interface_configurations:
     list[~azure.mgmt.compute.v2018_10_01.models.VirtualMachineScaleSetUpdateNetworkConfiguration]
    """

    _attribute_map = {
        'network_interface_configurations': {'key': 'networkInterfaceConfigurations', 'type': '[VirtualMachineScaleSetUpdateNetworkConfiguration]'},
    }

    def __init__(self, *, network_interface_configurations=None, **kwargs) -> None:
        super(VirtualMachineScaleSetUpdateNetworkProfile, self).__init__(**kwargs)
        self.network_interface_configurations = network_interface_configurations
