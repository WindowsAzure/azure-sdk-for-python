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

from .resource import Resource


class Table(Resource):
    """Represents an Azure SQL Database table.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Resource name
    :vartype name: str
    :ivar id: Resource ID
    :vartype id: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :ivar table_type: The type of Azure SQL Database table. Possible values
     include: 'BaseTable', 'View'
    :vartype table_type: str or :class:`TableType
     <azure.mgmt.sql.models.TableType>`
    :ivar columns: The columns from this table.
    :vartype columns: list of :class:`Column <azure.mgmt.sql.models.Column>`
    :ivar recommended_indexes: The recommended indices for this table.
    :vartype recommended_indexes: list of :class:`RecommendedIndex
     <azure.mgmt.sql.models.RecommendedIndex>`
    """

    _validation = {
        'name': {'readonly': True},
        'id': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'table_type': {'readonly': True},
        'columns': {'readonly': True},
        'recommended_indexes': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'table_type': {'key': 'properties.tableType', 'type': 'TableType'},
        'columns': {'key': 'properties.columns', 'type': '[Column]'},
        'recommended_indexes': {'key': 'properties.recommendedIndexes', 'type': '[RecommendedIndex]'},
    }

    def __init__(self, location, tags=None):
        super(Table, self).__init__(location=location, tags=tags)
        self.table_type = None
        self.columns = None
        self.recommended_indexes = None
