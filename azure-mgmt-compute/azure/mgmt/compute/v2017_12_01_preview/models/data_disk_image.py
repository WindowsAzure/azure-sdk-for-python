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


class DataDiskImage(Model):
    """Contains the data disk images information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar lun: Specifies the logical unit number of the data disk. This value
     is used to identify data disks within the VM and therefore must be unique
     for each data disk attached to a VM.
    :vartype lun: int
    """

    _validation = {
        'lun': {'readonly': True},
    }

    _attribute_map = {
        'lun': {'key': 'lun', 'type': 'int'},
    }

    def __init__(self):
        self.lun = None
