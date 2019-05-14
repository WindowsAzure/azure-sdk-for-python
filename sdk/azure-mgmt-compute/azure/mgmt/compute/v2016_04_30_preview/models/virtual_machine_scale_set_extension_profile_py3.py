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


class VirtualMachineScaleSetExtensionProfile(Model):
    """Describes a virtual machine scale set extension profile.

    :param extensions: The virtual machine scale set child extension
     resources.
    :type extensions:
     list[~azure.mgmt.compute.v2016_04_30_preview.models.VirtualMachineScaleSetExtension]
    """

    _attribute_map = {
        'extensions': {'key': 'extensions', 'type': '[VirtualMachineScaleSetExtension]'},
    }

    def __init__(self, *, extensions=None, **kwargs) -> None:
        super(VirtualMachineScaleSetExtensionProfile, self).__init__(**kwargs)
        self.extensions = extensions
