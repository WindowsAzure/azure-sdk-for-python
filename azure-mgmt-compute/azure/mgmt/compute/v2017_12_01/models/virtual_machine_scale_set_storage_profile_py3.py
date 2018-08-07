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


class VirtualMachineScaleSetStorageProfile(Model):
    """Describes a virtual machine scale set storage profile.

    :param image_reference: Specifies information about the image to use. You
     can specify information about platform images, marketplace images, or
     virtual machine images. This element is required when you want to use a
     platform image, marketplace image, or virtual machine image, but is not
     used in other creation operations.
    :type image_reference:
     ~azure.mgmt.compute.v2017_12_01.models.ImageReference
    :param os_disk: Specifies information about the operating system disk used
     by the virtual machines in the scale set. <br><br> For more information
     about disks, see [About disks and VHDs for Azure virtual
     machines](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-windows-about-disks-vhds?toc=%2fazure%2fvirtual-machines%2fwindows%2ftoc.json).
    :type os_disk:
     ~azure.mgmt.compute.v2017_12_01.models.VirtualMachineScaleSetOSDisk
    :param data_disks: Specifies the parameters that are used to add data
     disks to the virtual machines in the scale set. <br><br> For more
     information about disks, see [About disks and VHDs for Azure virtual
     machines](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-windows-about-disks-vhds?toc=%2fazure%2fvirtual-machines%2fwindows%2ftoc.json).
    :type data_disks:
     list[~azure.mgmt.compute.v2017_12_01.models.VirtualMachineScaleSetDataDisk]
    """

    _attribute_map = {
        'image_reference': {'key': 'imageReference', 'type': 'ImageReference'},
        'os_disk': {'key': 'osDisk', 'type': 'VirtualMachineScaleSetOSDisk'},
        'data_disks': {'key': 'dataDisks', 'type': '[VirtualMachineScaleSetDataDisk]'},
    }

    def __init__(self, *, image_reference=None, os_disk=None, data_disks=None, **kwargs) -> None:
        super(VirtualMachineScaleSetStorageProfile, self).__init__(**kwargs)
        self.image_reference = image_reference
        self.os_disk = os_disk
        self.data_disks = data_disks
