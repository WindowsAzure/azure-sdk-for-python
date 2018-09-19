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


class DatabaseStatistics(Model):
    """DatabaseStatistics.

    :param size: The database size - the total size of compressed data and
     index in bytes.
    :type size: float
    """

    _attribute_map = {
        'size': {'key': 'size', 'type': 'float'},
    }

    def __init__(self, **kwargs):
        super(DatabaseStatistics, self).__init__(**kwargs)
        self.size = kwargs.get('size', None)
