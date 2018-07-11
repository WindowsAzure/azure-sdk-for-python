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


class Disk(Model):
    """Specifies the disk information fo the HANA instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: The disk name.
    :type name: str
    :param disk_size_gb: Specifies the size of an empty data disk in
     gigabytes.
    :type disk_size_gb: int
    :ivar lun: Specifies the logical unit number of the data disk. This value
     is used to identify data disks within the VM and therefore must be unique
     for each data disk attached to a VM.
    :vartype lun: int
    """

    _validation = {
        'lun': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'disk_size_gb': {'key': 'diskSizeGB', 'type': 'int'},
        'lun': {'key': 'lun', 'type': 'int'},
    }

    def __init__(self, name=None, disk_size_gb=None):
        super(Disk, self).__init__()
        self.name = name
        self.disk_size_gb = disk_size_gb
        self.lun = None
