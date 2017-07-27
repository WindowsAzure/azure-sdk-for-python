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


class DiskInstanceView(Model):
    """The instance view of the disk.

    :param name: The disk name.
    :type name: str
    :param statuses: The resource status information.
    :type statuses: list of :class:`InstanceViewStatus
     <azure.mgmt.compute.compute.v2016_03_30.models.InstanceViewStatus>`
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'statuses': {'key': 'statuses', 'type': '[InstanceViewStatus]'},
    }

    def __init__(self, name=None, statuses=None):
        self.name = name
        self.statuses = statuses
