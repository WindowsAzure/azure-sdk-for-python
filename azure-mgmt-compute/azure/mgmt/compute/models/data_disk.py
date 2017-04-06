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

    :param lun: The logical unit number.
    :type lun: int
    :param name: The disk name.
    :type name: str
    :param vhd: The virtual hard disk.
    :type vhd: :class:`VirtualHardDisk
     <azure.mgmt.compute.models.VirtualHardDisk>`
    :param image: The source user image virtual hard disk. This virtual hard
     disk will be copied before using it to attach to the virtual machine. If
     SourceImage is provided, the destination virtual hard disk must not exist.
    :type image: :class:`VirtualHardDisk
     <azure.mgmt.compute.models.VirtualHardDisk>`
    :param caching: The caching type. Possible values include: 'None',
     'ReadOnly', 'ReadWrite'
    :type caching: str or :class:`CachingTypes
     <azure.mgmt.compute.models.CachingTypes>`
    :param create_option: The create option. Possible values include:
     'fromImage', 'empty', 'attach'
    :type create_option: str or :class:`DiskCreateOptionTypes
     <azure.mgmt.compute.models.DiskCreateOptionTypes>`
    :param disk_size_gb: The initial disk size in GB for blank data disks, and
     the new desired size for resizing existing OS and data disks.
    :type disk_size_gb: int
    :param managed_disk: The managed disk parameters.
    :type managed_disk: :class:`ManagedDiskParameters
     <azure.mgmt.compute.models.ManagedDiskParameters>`
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
        'create_option': {'key': 'createOption', 'type': 'DiskCreateOptionTypes'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'managed_disk': {'key': 'managedDisk', 'type': 'ManagedDiskParameters'},
    }

    def __init__(self, lun, create_option, name=None, vhd=None, image=None, caching=None, disk_size_gb=None, managed_disk=None):
        self.lun = lun
        self.name = name
        self.vhd = vhd
        self.image = image
        self.caching = caching
        self.create_option = create_option
        self.disk_size_gb = disk_size_gb
        self.managed_disk = managed_disk
