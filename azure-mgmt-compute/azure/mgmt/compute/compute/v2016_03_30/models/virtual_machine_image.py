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

from .virtual_machine_image_resource import VirtualMachineImageResource


class VirtualMachineImage(VirtualMachineImageResource):
    """Describes a Virtual Machine Image.

    :param id: Resource Id
    :type id: str
    :param name: The name of the resource.
    :type name: str
    :param location: The supported Azure location of the resource.
    :type location: str
    :param tags: The tags attached to the resource.
    :type tags: dict
    :param plan:
    :type plan: :class:`PurchasePlan
     <azure.mgmt.compute.compute.v2016_03_30.models.PurchasePlan>`
    :param os_disk_image:
    :type os_disk_image: :class:`OSDiskImage
     <azure.mgmt.compute.compute.v2016_03_30.models.OSDiskImage>`
    :param data_disk_images:
    :type data_disk_images: list of :class:`DataDiskImage
     <azure.mgmt.compute.compute.v2016_03_30.models.DataDiskImage>`
    """

    _validation = {
        'name': {'required': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'plan': {'key': 'properties.plan', 'type': 'PurchasePlan'},
        'os_disk_image': {'key': 'properties.osDiskImage', 'type': 'OSDiskImage'},
        'data_disk_images': {'key': 'properties.dataDiskImages', 'type': '[DataDiskImage]'},
    }

    def __init__(self, name, location, id=None, tags=None, plan=None, os_disk_image=None, data_disk_images=None):
        super(VirtualMachineImage, self).__init__(id=id, name=name, location=location, tags=tags)
        self.plan = plan
        self.os_disk_image = os_disk_image
        self.data_disk_images = data_disk_images
