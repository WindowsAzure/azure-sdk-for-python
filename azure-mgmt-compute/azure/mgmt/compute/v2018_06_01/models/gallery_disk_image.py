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


class GalleryDiskImage(Model):
    """This is the disk image base class.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar size_in_gb: It indicates the size of the VHD to create.
    :vartype size_in_gb: int
    :ivar host_caching: The host caching of the disk. Valid values are 'None',
     'ReadOnly', and 'ReadWrite'. Possible values include: 'None', 'ReadOnly',
     'ReadWrite'
    :vartype host_caching: str or
     ~azure.mgmt.compute.v2018_06_01.models.HostCaching
    """

    _validation = {
        'size_in_gb': {'readonly': True},
        'host_caching': {'readonly': True},
    }

    _attribute_map = {
        'size_in_gb': {'key': 'sizeInGB', 'type': 'int'},
        'host_caching': {'key': 'hostCaching', 'type': 'HostCaching'},
    }

    def __init__(self, **kwargs):
        super(GalleryDiskImage, self).__init__(**kwargs)
        self.size_in_gb = None
        self.host_caching = None
