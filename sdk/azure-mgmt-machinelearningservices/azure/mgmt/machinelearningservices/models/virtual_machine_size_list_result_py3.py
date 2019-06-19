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


class VirtualMachineSizeListResult(Model):
    """The List Virtual Machine size operation response.

    :param aml_compute: The list of virtual machine sizes supported by
     AmlCompute.
    :type aml_compute:
     list[~azure.mgmt.machinelearningservices.models.VirtualMachineSize]
    """

    _attribute_map = {
        'aml_compute': {'key': 'amlCompute', 'type': '[VirtualMachineSize]'},
    }

    def __init__(self, *, aml_compute=None, **kwargs) -> None:
        super(VirtualMachineSizeListResult, self).__init__(**kwargs)
        self.aml_compute = aml_compute
