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


class AttachNewDataDiskOptionsFragment(Model):
    """Properties to attach new disk to the Virtual Machine.

    :param disk_size_gi_b: Size of the disk to be attached in GibiBytes.
    :type disk_size_gi_b: int
    :param disk_name: The name of the disk to be attached.
    :type disk_name: str
    :param disk_type: The storage type for the disk (i.e. Standard, Premium).
     Possible values include: 'Standard', 'Premium'
    :type disk_type: str or ~azure.mgmt.devtestlabs.models.StorageType
    """

    _attribute_map = {
        'disk_size_gi_b': {'key': 'diskSizeGiB', 'type': 'int'},
        'disk_name': {'key': 'diskName', 'type': 'str'},
        'disk_type': {'key': 'diskType', 'type': 'str'},
    }

    def __init__(self, *, disk_size_gi_b: int=None, disk_name: str=None, disk_type=None, **kwargs) -> None:
        super(AttachNewDataDiskOptionsFragment, self).__init__(**kwargs)
        self.disk_size_gi_b = disk_size_gi_b
        self.disk_name = disk_name
        self.disk_type = disk_type
