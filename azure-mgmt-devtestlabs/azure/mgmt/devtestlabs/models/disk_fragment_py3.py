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

from .update_resource_py3 import UpdateResource


class DiskFragment(UpdateResource):
    """A Disk.

    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param disk_type: The storage type for the disk (i.e. Standard, Premium).
     Possible values include: 'Standard', 'Premium'
    :type disk_type: str or ~azure.mgmt.devtestlabs.models.StorageType
    :param disk_size_gi_b: The size of the disk in Gibibytes.
    :type disk_size_gi_b: int
    :param leased_by_lab_vm_id: The resource ID of the VM to which this disk
     is leased.
    :type leased_by_lab_vm_id: str
    :param disk_blob_name: When backed by a blob, the name of the VHD blob
     without extension.
    :type disk_blob_name: str
    :param disk_uri: When backed by a blob, the URI of underlying blob.
    :type disk_uri: str
    :param host_caching: The host caching policy of the disk (i.e. None,
     ReadOnly, ReadWrite).
    :type host_caching: str
    :param managed_disk_id: When backed by managed disk, this is the ID of the
     compute disk resource.
    :type managed_disk_id: str
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'disk_type': {'key': 'properties.diskType', 'type': 'str'},
        'disk_size_gi_b': {'key': 'properties.diskSizeGiB', 'type': 'int'},
        'leased_by_lab_vm_id': {'key': 'properties.leasedByLabVmId', 'type': 'str'},
        'disk_blob_name': {'key': 'properties.diskBlobName', 'type': 'str'},
        'disk_uri': {'key': 'properties.diskUri', 'type': 'str'},
        'host_caching': {'key': 'properties.hostCaching', 'type': 'str'},
        'managed_disk_id': {'key': 'properties.managedDiskId', 'type': 'str'},
    }

    def __init__(self, *, tags=None, disk_type=None, disk_size_gi_b: int=None, leased_by_lab_vm_id: str=None, disk_blob_name: str=None, disk_uri: str=None, host_caching: str=None, managed_disk_id: str=None, **kwargs) -> None:
        super(DiskFragment, self).__init__(tags=tags, **kwargs)
        self.disk_type = disk_type
        self.disk_size_gi_b = disk_size_gi_b
        self.leased_by_lab_vm_id = leased_by_lab_vm_id
        self.disk_blob_name = disk_blob_name
        self.disk_uri = disk_uri
        self.host_caching = host_caching
        self.managed_disk_id = managed_disk_id
