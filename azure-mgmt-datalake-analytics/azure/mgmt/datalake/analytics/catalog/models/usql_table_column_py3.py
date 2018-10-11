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


class USqlTableColumn(Model):
    """A Data Lake Analytics catalog U-SQL table column item.

    :param name: the name of the column in the table.
    :type name: str
    :param type: the object type of the specified column (such as
     System.String).
    :type type: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, type: str=None, **kwargs) -> None:
        super(USqlTableColumn, self).__init__(**kwargs)
        self.name = name
        self.type = type
