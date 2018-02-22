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


class ComponentPurgeBodyFilters(Model):
    """User-defined filters to return data which will be purged from the table.

    :param column: The column of the table over which the given query should
     run
    :type column: str
    :param filter: A query to to run over the provided table and column to
     purge the corresponding data.
    :type filter: str
    """

    _attribute_map = {
        'column': {'key': 'column', 'type': 'str'},
        'filter': {'key': 'filter', 'type': 'str'},
    }

    def __init__(self, column=None, filter=None):
        super(ComponentPurgeBodyFilters, self).__init__()
        self.column = column
        self.filter = filter
