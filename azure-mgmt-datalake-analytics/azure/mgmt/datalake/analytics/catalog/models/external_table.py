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


class ExternalTable(Model):
    """A Data Lake Analytics catalog external table item.

    :param table_name: the name of the table associated with this database
     and schema.
    :type table_name: str
    :param data_source: the data source associated with this external table.
    :type data_source: :class:`EntityId
     <azure.mgmt.datalake.analytics.catalog.models.EntityId>`
    """ 

    _attribute_map = {
        'table_name': {'key': 'tableName', 'type': 'str'},
        'data_source': {'key': 'dataSource', 'type': 'EntityId'},
    }

    def __init__(self, table_name=None, data_source=None):
        self.table_name = table_name
        self.data_source = data_source
