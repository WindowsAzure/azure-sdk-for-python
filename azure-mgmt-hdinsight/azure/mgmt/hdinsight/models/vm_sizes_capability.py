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


class VmSizesCapability(Model):
    """The virtual machine sizes capability.

    :param available: The list of virtual machine size capabilities.
    :type available: list[str]
    """

    _attribute_map = {
        'available': {'key': 'available', 'type': '[str]'},
    }

    def __init__(self, available=None):
        super(VmSizesCapability, self).__init__()
        self.available = available
