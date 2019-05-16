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


class FormulaPropertiesFromVmFragment(Model):
    """Information about a VM from which a formula is to be created.

    :param lab_vm_id: The identifier of the VM from which a formula is to be
     created.
    :type lab_vm_id: str
    """

    _attribute_map = {
        'lab_vm_id': {'key': 'labVmId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(FormulaPropertiesFromVmFragment, self).__init__(**kwargs)
        self.lab_vm_id = kwargs.get('lab_vm_id', None)
