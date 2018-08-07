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

    All required parameters must be populated in order to send to Azure.

    :param id: Resource Id
    :type id: str
    :param name: Required. The name of the resource.
    :type name: str
    :param location: Required. The supported Azure location of the resource.
    :type location: str
    :param tags: Specifies the tags that are assigned to the virtual machine.
     For more information about using tags, see [Using tags to organize your
     Azure
     resources](https://docs.microsoft.com/azure/azure-resource-manager/resource-group-using-tags.md).
    :type tags: dict[str, str]
    :param plan:
    :type plan: ~azure.mgmt.compute.v2018_04_01.models.PurchasePlan
    :param os_disk_image:
    :type os_disk_image: ~azure.mgmt.compute.v2018_04_01.models.OSDiskImage
    :param data_disk_images:
    :type data_disk_images:
     list[~azure.mgmt.compute.v2018_04_01.models.DataDiskImage]
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

    def __init__(self, **kwargs):
        super(VirtualMachineImage, self).__init__(**kwargs)
        self.plan = kwargs.get('plan', None)
        self.os_disk_image = kwargs.get('os_disk_image', None)
        self.data_disk_images = kwargs.get('data_disk_images', None)
