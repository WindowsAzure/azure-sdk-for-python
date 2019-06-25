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


class VirtualMachineSize(Model):
    """Describes the properties of a VM size.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Virtual Machine size name. The name of the virtual machine
     size.
    :vartype name: str
    :ivar family: Virtual Machine family name. The family name of the virtual
     machine size.
    :vartype family: str
    :ivar v_cp_us: Number of vPUs. The number of vCPUs supported by the
     virtual machine size.
    :vartype v_cp_us: int
    :ivar gpus: Number of gPUs. The number of gPUs supported by the virtual
     machine size.
    :vartype gpus: int
    :ivar os_vhd_size_mb: OS VHD Disk size. The OS VHD disk size, in MB,
     allowed by the virtual machine size.
    :vartype os_vhd_size_mb: int
    :ivar max_resource_volume_mb: Resource volume size. The resource volume
     size, in MB, allowed by the virtual machine size.
    :vartype max_resource_volume_mb: int
    :ivar memory_gb: Memory size. The amount of memory, in GB, supported by
     the virtual machine size.
    :vartype memory_gb: float
    :ivar low_priority_capable: Low priority capable. Specifies if the virtual
     machine size supports low priority VMs.
    :vartype low_priority_capable: bool
    :ivar premium_io: Premium IO supported. Specifies if the virtual machine
     size supports premium IO.
    :vartype premium_io: bool
    """

    _validation = {
        'name': {'readonly': True},
        'family': {'readonly': True},
        'v_cp_us': {'readonly': True},
        'gpus': {'readonly': True},
        'os_vhd_size_mb': {'readonly': True},
        'max_resource_volume_mb': {'readonly': True},
        'memory_gb': {'readonly': True},
        'low_priority_capable': {'readonly': True},
        'premium_io': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'family': {'key': 'family', 'type': 'str'},
        'v_cp_us': {'key': 'vCPUs', 'type': 'int'},
        'gpus': {'key': 'gpus', 'type': 'int'},
        'os_vhd_size_mb': {'key': 'osVhdSizeMB', 'type': 'int'},
        'max_resource_volume_mb': {'key': 'maxResourceVolumeMB', 'type': 'int'},
        'memory_gb': {'key': 'memoryGB', 'type': 'float'},
        'low_priority_capable': {'key': 'lowPriorityCapable', 'type': 'bool'},
        'premium_io': {'key': 'premiumIO', 'type': 'bool'},
    }

    def __init__(self, **kwargs) -> None:
        super(VirtualMachineSize, self).__init__(**kwargs)
        self.name = None
        self.family = None
        self.v_cp_us = None
        self.gpus = None
        self.os_vhd_size_mb = None
        self.max_resource_volume_mb = None
        self.memory_gb = None
        self.low_priority_capable = None
        self.premium_io = None
