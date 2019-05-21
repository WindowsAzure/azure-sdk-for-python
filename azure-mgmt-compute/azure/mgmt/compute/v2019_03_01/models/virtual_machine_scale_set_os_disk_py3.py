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

    All required parameters must be populated in order to send to Azure.

    :param name: The disk name.
    :type name: str
    :param caching: Specifies the caching requirements. <br><br> Possible
     values are: <br><br> **None** <br><br> **ReadOnly** <br><br> **ReadWrite**
     <br><br> Default: **None for Standard storage. ReadOnly for Premium
     storage**. Possible values include: 'None', 'ReadOnly', 'ReadWrite'
    :type caching: str or ~azure.mgmt.compute.v2019_03_01.models.CachingTypes
    :param write_accelerator_enabled: Specifies whether writeAccelerator
     should be enabled or disabled on the disk.
    :type write_accelerator_enabled: bool
    :param create_option: Required. Specifies how the virtual machines in the
     scale set should be created.<br><br> The only allowed value is:
     **FromImage** \\u2013 This value is used when you are using an image to
     create the virtual machine. If you are using a platform image, you also
     use the imageReference element described above. If you are using a
     marketplace image, you  also use the plan element previously described.
     Possible values include: 'FromImage', 'Empty', 'Attach'
    :type create_option: str or
     ~azure.mgmt.compute.v2019_03_01.models.DiskCreateOptionTypes
    :param diff_disk_settings: Specifies the ephemeral disk Settings for the
     operating system disk used by the virtual machine scale set.
    :type diff_disk_settings:
     ~azure.mgmt.compute.v2019_03_01.models.DiffDiskSettings
    :param disk_size_gb: Specifies the size of the operating system disk in
     gigabytes. This element can be used to overwrite the size of the disk in a
     virtual machine image. <br><br> This value cannot be larger than 1023 GB
    :type disk_size_gb: int
    :param os_type: This property allows you to specify the type of the OS
     that is included in the disk if creating a VM from user-image or a
     specialized VHD. <br><br> Possible values are: <br><br> **Windows**
     <br><br> **Linux**. Possible values include: 'Windows', 'Linux'
    :type os_type: str or
     ~azure.mgmt.compute.v2019_03_01.models.OperatingSystemTypes
    :param image: Specifies information about the unmanaged user image to base
     the scale set on.
    :type image: ~azure.mgmt.compute.v2019_03_01.models.VirtualHardDisk
    :param vhd_containers: Specifies the container urls that are used to store
     operating system disks for the scale set.
    :type vhd_containers: list[str]
    :param managed_disk: The managed disk parameters.
    :type managed_disk:
     ~azure.mgmt.compute.v2019_03_01.models.VirtualMachineScaleSetManagedDiskParameters
    """

    _validation = {
        'create_option': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'caching': {'key': 'caching', 'type': 'CachingTypes'},
        'write_accelerator_enabled': {'key': 'writeAcceleratorEnabled', 'type': 'bool'},
        'create_option': {'key': 'createOption', 'type': 'str'},
        'diff_disk_settings': {'key': 'diffDiskSettings', 'type': 'DiffDiskSettings'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'os_type': {'key': 'osType', 'type': 'OperatingSystemTypes'},
        'image': {'key': 'image', 'type': 'VirtualHardDisk'},
        'vhd_containers': {'key': 'vhdContainers', 'type': '[str]'},
        'managed_disk': {'key': 'managedDisk', 'type': 'VirtualMachineScaleSetManagedDiskParameters'},
    }

    def __init__(self, *, create_option, name: str=None, caching=None, write_accelerator_enabled: bool=None, diff_disk_settings=None, disk_size_gb: int=None, os_type=None, image=None, vhd_containers=None, managed_disk=None, **kwargs) -> None:
        super(VirtualMachineScaleSetOSDisk, self).__init__(**kwargs)
        self.name = name
        self.caching = caching
        self.write_accelerator_enabled = write_accelerator_enabled
        self.create_option = create_option
        self.diff_disk_settings = diff_disk_settings
        self.disk_size_gb = disk_size_gb
        self.os_type = os_type
        self.image = image
        self.vhd_containers = vhd_containers
        self.managed_disk = managed_disk
