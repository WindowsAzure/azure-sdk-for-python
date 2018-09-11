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


class SystemIntPtr(Model):
    """SystemIntPtr.

    :param size:
    :type size: int
    """

    _attribute_map = {
        'size': {'key': 'Size', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(SystemIntPtr, self).__init__(**kwargs)
        self.size = kwargs.get('size', None)
