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


class VirtualMachineScaleSetVMProtectionPolicy(Model):
    """The protection policy of a virtual machine scale set VM.

    :param protect_from_scale_in: Indicates that the virtual machine scale set
     VM shouldn't be considered for deletion during a scale-in operation.
    :type protect_from_scale_in: bool
    :param protect_from_scale_set_actions: Indicates that model updates or
     actions (including scale-in) initiated on the virtual machine scale set
     should not be applied to the virtual machine scale set VM.
    :type protect_from_scale_set_actions: bool
    """

    _attribute_map = {
        'protect_from_scale_in': {'key': 'protectFromScaleIn', 'type': 'bool'},
        'protect_from_scale_set_actions': {'key': 'protectFromScaleSetActions', 'type': 'bool'},
    }

    def __init__(self, *, protect_from_scale_in: bool=None, protect_from_scale_set_actions: bool=None, **kwargs) -> None:
        super(VirtualMachineScaleSetVMProtectionPolicy, self).__init__(**kwargs)
        self.protect_from_scale_in = protect_from_scale_in
        self.protect_from_scale_set_actions = protect_from_scale_set_actions
