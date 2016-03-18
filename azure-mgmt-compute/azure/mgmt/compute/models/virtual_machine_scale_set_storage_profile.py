# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class VirtualMachineScaleSetStorageProfile(Model):
    """
    Describes a virtual machine scale set storage profile.

    :param image_reference: Gets or sets the image reference.
    :type image_reference: :class:`ImageReference
     <azure.mgmt.compute.models.ImageReference>`
    :param os_disk: Gets or sets the OS disk.
    :type os_disk: :class:`VirtualMachineScaleSetOSDisk
     <azure.mgmt.compute.models.VirtualMachineScaleSetOSDisk>`
    """ 

    _attribute_map = {
        'image_reference': {'key': 'imageReference', 'type': 'ImageReference'},
        'os_disk': {'key': 'osDisk', 'type': 'VirtualMachineScaleSetOSDisk'},
    }

    def __init__(self, image_reference=None, os_disk=None, **kwargs):
        self.image_reference = image_reference
        self.os_disk = os_disk
