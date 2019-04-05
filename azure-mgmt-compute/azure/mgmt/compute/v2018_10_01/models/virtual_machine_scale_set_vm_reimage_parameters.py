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

from .virtual_machine_reimage_parameters import VirtualMachineReimageParameters


class VirtualMachineScaleSetVMReimageParameters(VirtualMachineReimageParameters):
    """Describes a Virtual Machine Scale Set VM Reimage Parameters.

    :param temp_disk: Specifies whether to reimage temp disk. Default value:
     false.
    :type temp_disk: bool
    """

    _attribute_map = {
        'temp_disk': {'key': 'tempDisk', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(VirtualMachineScaleSetVMReimageParameters, self).__init__(**kwargs)
