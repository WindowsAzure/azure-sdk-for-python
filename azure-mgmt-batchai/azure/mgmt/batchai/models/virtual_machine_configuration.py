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


class VirtualMachineConfiguration(Model):
    """Settings for OS image.

    :param image_reference: Reference to OS image.
    :type image_reference: ~azure.mgmt.batchai.models.ImageReference
    """

    _attribute_map = {
        'image_reference': {'key': 'imageReference', 'type': 'ImageReference'},
    }

    def __init__(self, image_reference=None):
        super(VirtualMachineConfiguration, self).__init__()
        self.image_reference = image_reference
