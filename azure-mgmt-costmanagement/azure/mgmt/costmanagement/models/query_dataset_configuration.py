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


class QueryDatasetConfiguration(Model):
    """The configuration of dataset in the query.

    :param columns: Array of column names to be included in the query. Any
     valid query column name is allowed. If not provided, then query includes
     all columns.
    :type columns: list[str]
    """

    _attribute_map = {
        'columns': {'key': 'columns', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(QueryDatasetConfiguration, self).__init__(**kwargs)
        self.columns = kwargs.get('columns', None)
