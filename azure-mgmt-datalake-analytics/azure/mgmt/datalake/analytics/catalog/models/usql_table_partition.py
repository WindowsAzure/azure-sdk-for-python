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

from .catalog_item import CatalogItem


class USqlTablePartition(CatalogItem):
    """A Data Lake Analytics catalog U-SQL table partition item.

    :param compute_account_name: the name of the Data Lake Analytics account.
    :type compute_account_name: str
    :param version: the version of the catalog item.
    :type version: str
    :param database_name: the name of the database.
    :type database_name: str
    :param schema_name: the name of the schema associated with this table
     partition and database.
    :type schema_name: str
    :param name: the name of the table partition.
    :type name: str
    :param parent_name: the Ddl object of the partition's parent.
    :type parent_name: :class:`DdlName
     <azure.mgmt.datalake.analytics.catalog.models.DdlName>`
    :param index_id: the index ID for this partition.
    :type index_id: int
    :param label: the list of labels associated with this partition.
    :type label: list of str
    :param create_date: the creation time of the partition
    :type create_date: datetime
    """ 

    _attribute_map = {
        'compute_account_name': {'key': 'computeAccountName', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'database_name': {'key': 'databaseName', 'type': 'str'},
        'schema_name': {'key': 'schemaName', 'type': 'str'},
        'name': {'key': 'partitionName', 'type': 'str'},
        'parent_name': {'key': 'parentName', 'type': 'DdlName'},
        'index_id': {'key': 'indexId', 'type': 'int'},
        'label': {'key': 'label', 'type': '[str]'},
        'create_date': {'key': 'createDate', 'type': 'iso-8601'},
    }

    def __init__(self, compute_account_name=None, version=None, database_name=None, schema_name=None, name=None, parent_name=None, index_id=None, label=None, create_date=None):
        super(USqlTablePartition, self).__init__(compute_account_name=compute_account_name, version=version)
        self.database_name = database_name
        self.schema_name = schema_name
        self.name = name
        self.parent_name = parent_name
        self.index_id = index_id
        self.label = label
        self.create_date = create_date
