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


class VirtualMachineScaleSetDataDisk(Model):
    """Describes a virtual machine scale set data disk.

    :param name: The disk name.
    :type name: str
    :param lun: Specifies the logical unit number of the data disk. This value
     is used to identify data disks within the VM and therefore must be unique
     for each data disk attached to a VM.
    :type lun: int
    :param caching: Specifies the caching requirements. <br><br> Possible
     values are: <br><br> **None** <br><br> **ReadOnly** <br><br> **ReadWrite**
     <br><br> Default: **None for Standard storage. ReadOnly for Premium
     storage**. Possible values include: 'None', 'ReadOnly', 'ReadWrite'
    :type caching: str or
     ~azure.mgmt.compute.v2017_12_01_preview.models.CachingTypes
    :param create_option: The create option. Possible values include:
     'FromImage', 'Empty', 'Attach'
    :type create_option: str or
     ~azure.mgmt.compute.v2017_12_01_preview.models.DiskCreateOptionTypes
    :param disk_size_gb: Specifies the size of an empty data disk in
     gigabytes. This element can be used to overwrite the name of the disk in a
     virtual machine image. <br><br> This value cannot be larger than 1023 GB
    :type disk_size_gb: int
    :param managed_disk: The managed disk parameters.
    :type managed_disk:
     ~azure.mgmt.compute.v2017_12_01_preview.models.VirtualMachineScaleSetManagedDiskParameters
    """

    _validation = {
        'lun': {'required': True},
        'create_option': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'lun': {'key': 'lun', 'type': 'int'},
        'caching': {'key': 'caching', 'type': 'CachingTypes'},
        'create_option': {'key': 'createOption', 'type': 'DiskCreateOptionTypes'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'managed_disk': {'key': 'managedDisk', 'type': 'VirtualMachineScaleSetManagedDiskParameters'},
    }

    def __init__(self, lun, create_option, name=None, caching=None, disk_size_gb=None, managed_disk=None):
        self.name = name
        self.lun = lun
        self.caching = caching
        self.create_option = create_option
        self.disk_size_gb = disk_size_gb
        self.managed_disk = managed_disk
