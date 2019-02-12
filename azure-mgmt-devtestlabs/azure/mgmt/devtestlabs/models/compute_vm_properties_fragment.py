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


class ComputeVmPropertiesFragment(Model):
    """Properties of a virtual machine returned by the Microsoft.Compute API.

    :param statuses: Gets the statuses of the virtual machine.
    :type statuses:
     list[~azure.mgmt.devtestlabs.models.ComputeVmInstanceViewStatusFragment]
    :param os_type: Gets the OS type of the virtual machine.
    :type os_type: str
    :param vm_size: Gets the size of the virtual machine.
    :type vm_size: str
    :param network_interface_id: Gets the network interface ID of the virtual
     machine.
    :type network_interface_id: str
    :param os_disk_id: Gets OS disk blob uri for the virtual machine.
    :type os_disk_id: str
    :param data_disk_ids: Gets data disks blob uri for the virtual machine.
    :type data_disk_ids: list[str]
    :param data_disks: Gets all data disks attached to the virtual machine.
    :type data_disks:
     list[~azure.mgmt.devtestlabs.models.ComputeDataDiskFragment]
    """

    _attribute_map = {
        'statuses': {'key': 'statuses', 'type': '[ComputeVmInstanceViewStatusFragment]'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'network_interface_id': {'key': 'networkInterfaceId', 'type': 'str'},
        'os_disk_id': {'key': 'osDiskId', 'type': 'str'},
        'data_disk_ids': {'key': 'dataDiskIds', 'type': '[str]'},
        'data_disks': {'key': 'dataDisks', 'type': '[ComputeDataDiskFragment]'},
    }

    def __init__(self, **kwargs):
        super(ComputeVmPropertiesFragment, self).__init__(**kwargs)
        self.statuses = kwargs.get('statuses', None)
        self.os_type = kwargs.get('os_type', None)
        self.vm_size = kwargs.get('vm_size', None)
        self.network_interface_id = kwargs.get('network_interface_id', None)
        self.os_disk_id = kwargs.get('os_disk_id', None)
        self.data_disk_ids = kwargs.get('data_disk_ids', None)
        self.data_disks = kwargs.get('data_disks', None)
