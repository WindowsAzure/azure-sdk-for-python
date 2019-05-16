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


class ResourceSettingCreationParameters(Model):
    """Represents resource specific settings.

    All required parameters must be populated in order to send to Azure.

    :param location: The location where the virtual machine will live
    :type location: str
    :param name: The name of the resource setting
    :type name: str
    :param gallery_image_resource_id: Required. The resource id of the gallery
     image used for creating the virtual machine
    :type gallery_image_resource_id: str
    :param size: The size of the virtual machine. Possible values include:
     'Basic', 'Standard', 'Performance'
    :type size: str or ~azure.mgmt.labservices.models.ManagedLabVmSize
    :param reference_vm_creation_parameters: Required. Creation parameters for
     Reference Vm
    :type reference_vm_creation_parameters:
     ~azure.mgmt.labservices.models.ReferenceVmCreationParameters
    """

    _validation = {
        'gallery_image_resource_id': {'required': True},
        'reference_vm_creation_parameters': {'required': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'gallery_image_resource_id': {'key': 'galleryImageResourceId', 'type': 'str'},
        'size': {'key': 'size', 'type': 'str'},
        'reference_vm_creation_parameters': {'key': 'referenceVmCreationParameters', 'type': 'ReferenceVmCreationParameters'},
    }

    def __init__(self, **kwargs):
        super(ResourceSettingCreationParameters, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.name = kwargs.get('name', None)
        self.gallery_image_resource_id = kwargs.get('gallery_image_resource_id', None)
        self.size = kwargs.get('size', None)
        self.reference_vm_creation_parameters = kwargs.get('reference_vm_creation_parameters', None)
