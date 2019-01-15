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


class VirtualMachineReimageParameters(Model):
    """Parameters for Reimaging Virtual Machine. NOTE: Virtual Machine OS disk
    will always be reimaged.

    :param temp_disk: Specifies whether to reimage temp disk. Default value:
     false.
    :type temp_disk: bool
    """

    _attribute_map = {
        'temp_disk': {'key': 'tempDisk', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(VirtualMachineReimageParameters, self).__init__(**kwargs)
        self.temp_disk = kwargs.get('temp_disk', None)
