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


class VirtualMachineScaleSetVMProfile(Model):
    """Describes a virtual machine scale set virtual machine profile.

    :param os_profile: Specifies the operating system settings for the virtual
     machines in the scale set.
    :type os_profile:
     ~azure.mgmt.compute.v2017_12_01.models.VirtualMachineScaleSetOSProfile
    :param storage_profile: Specifies the storage settings for the virtual
     machine disks.
    :type storage_profile:
     ~azure.mgmt.compute.v2017_12_01.models.VirtualMachineScaleSetStorageProfile
    :param network_profile: Specifies properties of the network interfaces of
     the virtual machines in the scale set.
    :type network_profile:
     ~azure.mgmt.compute.v2017_12_01.models.VirtualMachineScaleSetNetworkProfile
    :param diagnostics_profile: Specifies the boot diagnostic settings state.
     <br><br>Minimum api-version: 2015-06-15.
    :type diagnostics_profile:
     ~azure.mgmt.compute.v2017_12_01.models.DiagnosticsProfile
    :param extension_profile: Specifies a collection of settings for
     extensions installed on virtual machines in the scale set.
    :type extension_profile:
     ~azure.mgmt.compute.v2017_12_01.models.VirtualMachineScaleSetExtensionProfile
    :param license_type: Specifies that the image or disk that is being used
     was licensed on-premises. This element is only used for images that
     contain the Windows Server operating system. <br><br> Possible values are:
     <br><br> Windows_Client <br><br> Windows_Server <br><br> If this element
     is included in a request for an update, the value must match the initial
     value. This value cannot be updated. <br><br> For more information, see
     [Azure Hybrid Use Benefit for Windows
     Server](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-windows-hybrid-use-benefit-licensing?toc=%2fazure%2fvirtual-machines%2fwindows%2ftoc.json)
     <br><br> Minimum api-version: 2015-06-15
    :type license_type: str
    :param priority: Specifies the priority for the virtual machines in the
     scale set. <br><br>Minimum api-version: 2017-10-30-preview. Possible
     values include: 'Regular', 'Low'
    :type priority: str or
     ~azure.mgmt.compute.v2017_12_01.models.VirtualMachinePriorityTypes
    """

    _attribute_map = {
        'os_profile': {'key': 'osProfile', 'type': 'VirtualMachineScaleSetOSProfile'},
        'storage_profile': {'key': 'storageProfile', 'type': 'VirtualMachineScaleSetStorageProfile'},
        'network_profile': {'key': 'networkProfile', 'type': 'VirtualMachineScaleSetNetworkProfile'},
        'diagnostics_profile': {'key': 'diagnosticsProfile', 'type': 'DiagnosticsProfile'},
        'extension_profile': {'key': 'extensionProfile', 'type': 'VirtualMachineScaleSetExtensionProfile'},
        'license_type': {'key': 'licenseType', 'type': 'str'},
        'priority': {'key': 'priority', 'type': 'str'},
    }

    def __init__(self, *, os_profile=None, storage_profile=None, network_profile=None, diagnostics_profile=None, extension_profile=None, license_type: str=None, priority=None, **kwargs) -> None:
        super(VirtualMachineScaleSetVMProfile, self).__init__(**kwargs)
        self.os_profile = os_profile
        self.storage_profile = storage_profile
        self.network_profile = network_profile
        self.diagnostics_profile = diagnostics_profile
        self.extension_profile = extension_profile
        self.license_type = license_type
        self.priority = priority
