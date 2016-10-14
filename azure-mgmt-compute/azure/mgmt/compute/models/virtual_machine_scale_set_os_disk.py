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


class VirtualMachineScaleSetOSDisk(Model):
    """Describes a virtual machine scale set operating system disk.

    :param name: the disk name.
    :type name: str
    :param caching: the caching type. Possible values include: 'None',
     'ReadOnly', 'ReadWrite'
    :type caching: str or :class:`CachingTypes
     <azure.mgmt.compute.models.CachingTypes>`
    :param create_option: the create option. Possible values include:
     'fromImage', 'empty', 'attach'
    :type create_option: str or :class:`DiskCreateOptionTypes
     <azure.mgmt.compute.models.DiskCreateOptionTypes>`
    :param os_type: the Operating System type. Possible values include:
     'Windows', 'Linux'
    :type os_type: str or :class:`OperatingSystemTypes
     <azure.mgmt.compute.models.OperatingSystemTypes>`
    :param image: the Source User Image VirtualHardDisk. This VirtualHardDisk
     will be copied before using it to attach to the Virtual Machine. If
     SourceImage is provided, the destination VirtualHardDisk should not
     exist.
    :type image: :class:`VirtualHardDisk
     <azure.mgmt.compute.models.VirtualHardDisk>`
    :param vhd_containers: the list of virtual hard disk container uris.
    :type vhd_containers: list of str
    """ 

    _validation = {
        'name': {'required': True},
        'create_option': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'caching': {'key': 'caching', 'type': 'CachingTypes'},
        'create_option': {'key': 'createOption', 'type': 'DiskCreateOptionTypes'},
        'os_type': {'key': 'osType', 'type': 'OperatingSystemTypes'},
        'image': {'key': 'image', 'type': 'VirtualHardDisk'},
        'vhd_containers': {'key': 'vhdContainers', 'type': '[str]'},
    }

    def __init__(self, name, create_option, caching=None, os_type=None, image=None, vhd_containers=None):
        self.name = name
        self.caching = caching
        self.create_option = create_option
        self.os_type = os_type
        self.image = image
        self.vhd_containers = vhd_containers
