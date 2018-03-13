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


class VirtualDirectory(Model):
    """Directory for virtual application.

    :param virtual_path: Path to virtual application.
    :type virtual_path: str
    :param physical_path: Physical path.
    :type physical_path: str
    """

    _attribute_map = {
        'virtual_path': {'key': 'virtualPath', 'type': 'str'},
        'physical_path': {'key': 'physicalPath', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(VirtualDirectory, self).__init__(**kwargs)
        self.virtual_path = kwargs.get('virtual_path', None)
        self.physical_path = kwargs.get('physical_path', None)
