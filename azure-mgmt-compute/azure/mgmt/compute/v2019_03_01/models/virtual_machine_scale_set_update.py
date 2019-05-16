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

from .update_resource import UpdateResource


class VirtualMachineScaleSetUpdate(UpdateResource):
    """Describes a Virtual Machine Scale Set.

    :param tags: Resource tags
    :type tags: dict[str, str]
    :param sku: The virtual machine scale set sku.
    :type sku: ~azure.mgmt.compute.v2019_03_01.models.Sku
    :param plan: The purchase plan when deploying a virtual machine scale set
     from VM Marketplace images.
    :type plan: ~azure.mgmt.compute.v2019_03_01.models.Plan
    :param upgrade_policy: The upgrade policy.
    :type upgrade_policy: ~azure.mgmt.compute.v2019_03_01.models.UpgradePolicy
    :param virtual_machine_profile: The virtual machine profile.
    :type virtual_machine_profile:
     ~azure.mgmt.compute.v2019_03_01.models.VirtualMachineScaleSetUpdateVMProfile
    :param overprovision: Specifies whether the Virtual Machine Scale Set
     should be overprovisioned.
    :type overprovision: bool
    :param single_placement_group: When true this limits the scale set to a
     single placement group, of max size 100 virtual machines.
    :type single_placement_group: bool
    :param additional_capabilities: Specifies additional capabilities enabled
     or disabled on the Virtual Machines in the Virtual Machine Scale Set. For
     instance: whether the Virtual Machines have the capability to support
     attaching managed data disks with UltraSSD_LRS storage account type.
    :type additional_capabilities:
     ~azure.mgmt.compute.v2019_03_01.models.AdditionalCapabilities
    :param identity: The identity of the virtual machine scale set, if
     configured.
    :type identity:
     ~azure.mgmt.compute.v2019_03_01.models.VirtualMachineScaleSetIdentity
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'plan': {'key': 'plan', 'type': 'Plan'},
        'upgrade_policy': {'key': 'properties.upgradePolicy', 'type': 'UpgradePolicy'},
        'virtual_machine_profile': {'key': 'properties.virtualMachineProfile', 'type': 'VirtualMachineScaleSetUpdateVMProfile'},
        'overprovision': {'key': 'properties.overprovision', 'type': 'bool'},
        'single_placement_group': {'key': 'properties.singlePlacementGroup', 'type': 'bool'},
        'additional_capabilities': {'key': 'properties.additionalCapabilities', 'type': 'AdditionalCapabilities'},
        'identity': {'key': 'identity', 'type': 'VirtualMachineScaleSetIdentity'},
    }

    def __init__(self, **kwargs):
        super(VirtualMachineScaleSetUpdate, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.plan = kwargs.get('plan', None)
        self.upgrade_policy = kwargs.get('upgrade_policy', None)
        self.virtual_machine_profile = kwargs.get('virtual_machine_profile', None)
        self.overprovision = kwargs.get('overprovision', None)
        self.single_placement_group = kwargs.get('single_placement_group', None)
        self.additional_capabilities = kwargs.get('additional_capabilities', None)
        self.identity = kwargs.get('identity', None)
