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


class USqlDirectedColumn(Model):
    """A Data Lake Analytics catalog U-SQL directed column item.

    :param name: the name of the index in the table.
    :type name: str
    :param descending: the switch indicating if the index is descending or
     not.
    :type descending: bool
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'descending': {'key': 'descending', 'type': 'bool'},
    }

    def __init__(self, name=None, descending=None):
        self.name = name
        self.descending = descending
