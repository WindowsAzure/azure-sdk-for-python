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


class Table(Model):
    """A query response table.

    Contains the columns and rows for one table in a query response.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the table.
    :type name: str
    :param columns: Required. The list of columns in this table.
    :type columns: list[~azure.loganalytics.models.Column]
    :param rows: Required. The resulting rows from this query.
    :type rows: list[list[str]]
    """

    _validation = {
        'name': {'required': True},
        'columns': {'required': True},
        'rows': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'columns': {'key': 'columns', 'type': '[Column]'},
        'rows': {'key': 'rows', 'type': '[[str]]'},
    }

    def __init__(self, *, name: str, columns, rows, **kwargs) -> None:
        super(Table, self).__init__(**kwargs)
        self.name = name
        self.columns = columns
        self.rows = rows
