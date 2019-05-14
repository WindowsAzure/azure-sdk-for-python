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


class DataDisk(Model):
    """Describes a data disk.

    All required parameters must be populated in order to send to Azure.

    :param lun: Required. Specifies the logical unit number of the data disk.
     This value is used to identify data disks within the VM and therefore must
     be unique for each data disk attached to a VM.
    :type lun: int
    :param name: The disk name.
    :type name: str
    :param vhd: The virtual hard disk.
    :type vhd: ~azure.mgmt.compute.v2018_10_01.models.VirtualHardDisk
    :param image: The source user image virtual hard disk. The virtual hard
     disk will be copied before being attached to the virtual machine. If
     SourceImage is provided, the destination virtual hard drive must not
     exist.
    :type image: ~azure.mgmt.compute.v2018_10_01.models.VirtualHardDisk
    :param caching: Specifies the caching requirements. <br><br> Possible
     values are: <br><br> **None** <br><br> **ReadOnly** <br><br> **ReadWrite**
     <br><br> Default: **None for Standard storage. ReadOnly for Premium
     storage**. Possible values include: 'None', 'ReadOnly', 'ReadWrite'
    :type caching: str or ~azure.mgmt.compute.v2018_10_01.models.CachingTypes
    :param write_accelerator_enabled: Specifies whether writeAccelerator
     should be enabled or disabled on the disk.
    :type write_accelerator_enabled: bool
    :param create_option: Required. Specifies how the virtual machine should
     be created.<br><br> Possible values are:<br><br> **Attach** \\u2013 This
     value is used when you are using a specialized disk to create the virtual
     machine.<br><br> **FromImage** \\u2013 This value is used when you are
     using an image to create the virtual machine. If you are using a platform
     image, you also use the imageReference element described above. If you are
     using a marketplace image, you  also use the plan element previously
     described. Possible values include: 'FromImage', 'Empty', 'Attach'
    :type create_option: str or
     ~azure.mgmt.compute.v2018_10_01.models.DiskCreateOptionTypes
    :param disk_size_gb: Specifies the size of an empty data disk in
     gigabytes. This element can be used to overwrite the size of the disk in a
     virtual machine image. <br><br> This value cannot be larger than 1023 GB
    :type disk_size_gb: int
    :param managed_disk: The managed disk parameters.
    :type managed_disk:
     ~azure.mgmt.compute.v2018_10_01.models.ManagedDiskParameters
    """

    _validation = {
        'lun': {'required': True},
        'create_option': {'required': True},
    }

    _attribute_map = {
        'lun': {'key': 'lun', 'type': 'int'},
        'name': {'key': 'name', 'type': 'str'},
        'vhd': {'key': 'vhd', 'type': 'VirtualHardDisk'},
        'image': {'key': 'image', 'type': 'VirtualHardDisk'},
        'caching': {'key': 'caching', 'type': 'CachingTypes'},
        'write_accelerator_enabled': {'key': 'writeAcceleratorEnabled', 'type': 'bool'},
        'create_option': {'key': 'createOption', 'type': 'str'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'managed_disk': {'key': 'managedDisk', 'type': 'ManagedDiskParameters'},
    }

    def __init__(self, **kwargs):
        super(DataDisk, self).__init__(**kwargs)
        self.lun = kwargs.get('lun', None)
        self.name = kwargs.get('name', None)
        self.vhd = kwargs.get('vhd', None)
        self.image = kwargs.get('image', None)
        self.caching = kwargs.get('caching', None)
        self.write_accelerator_enabled = kwargs.get('write_accelerator_enabled', None)
        self.create_option = kwargs.get('create_option', None)
        self.disk_size_gb = kwargs.get('disk_size_gb', None)
        self.managed_disk = kwargs.get('managed_disk', None)
