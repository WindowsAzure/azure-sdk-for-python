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


class ImageStorageProfile(Model):
    """Describes a storage profile.

    :param os_disk: Specifies information about the operating system disk used
     by the virtual machine. <br><br> For more information about disks, see
     [About disks and VHDs for Azure virtual
     machines](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-windows-about-disks-vhds?toc=%2fazure%2fvirtual-machines%2fwindows%2ftoc.json).
    :type os_disk: ~azure.mgmt.compute.v2018_10_01.models.ImageOSDisk
    :param data_disks: Specifies the parameters that are used to add a data
     disk to a virtual machine. <br><br> For more information about disks, see
     [About disks and VHDs for Azure virtual
     machines](https://docs.microsoft.com/azure/virtual-machines/virtual-machines-windows-about-disks-vhds?toc=%2fazure%2fvirtual-machines%2fwindows%2ftoc.json).
    :type data_disks:
     list[~azure.mgmt.compute.v2018_10_01.models.ImageDataDisk]
    :param zone_resilient: Specifies whether an image is zone resilient or
     not. Default is false. Zone resilient images can be created only in
     regions that provide Zone Redundant Storage (ZRS).
    :type zone_resilient: bool
    """

    _attribute_map = {
        'os_disk': {'key': 'osDisk', 'type': 'ImageOSDisk'},
        'data_disks': {'key': 'dataDisks', 'type': '[ImageDataDisk]'},
        'zone_resilient': {'key': 'zoneResilient', 'type': 'bool'},
    }

    def __init__(self, *, os_disk=None, data_disks=None, zone_resilient: bool=None, **kwargs) -> None:
        super(ImageStorageProfile, self).__init__(**kwargs)
        self.os_disk = os_disk
        self.data_disks = data_disks
        self.zone_resilient = zone_resilient
