# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .catalog_item import CatalogItem


class USqlTableStatistics(CatalogItem):
    """
    A Data Lake Analytics catalog U-SQL table statistics item.

    :param compute_account_name: the name of the Data Lake Analytics account.
    :type compute_account_name: str
    :param version: the version of the catalog item.
    :type version: str
    :param database_name: the name of the database.
    :type database_name: str
    :param schema_name: the name of the schema associated with this table and
     database.
    :type schema_name: str
    :param table_name: the name of the table.
    :type table_name: str
    :param name: the name of the table statistics.
    :type name: str
    :param user_stat_name: the name of the user statistics.
    :type user_stat_name: str
    :param stat_data_path: the path to the statistics data.
    :type stat_data_path: str
    :param create_time: the creation time of the statistics.
    :type create_time: datetime
    :param update_time: the last time the statistics were updated.
    :type update_time: datetime
    :param is_user_created: the switch indicating if these statistics are
     user created.
    :type is_user_created: bool
    :param is_auto_created: the switch indicating if these statistics are
     automatically created.
    :type is_auto_created: bool
    :param has_filter: the switch indicating if these statistics have a
     filter.
    :type has_filter: bool
    :param filter_definition: the filter definition for the statistics.
    :type filter_definition: str
    :param col_names: the list of column names associated with these
     statistics.
    :type col_names: list of str
    """ 

    _attribute_map = {
        'compute_account_name': {'key': 'computeAccountName', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'database_name': {'key': 'databaseName', 'type': 'str'},
        'schema_name': {'key': 'schemaName', 'type': 'str'},
        'table_name': {'key': 'tableName', 'type': 'str'},
        'name': {'key': 'statisticsName', 'type': 'str'},
        'user_stat_name': {'key': 'userStatName', 'type': 'str'},
        'stat_data_path': {'key': 'statDataPath', 'type': 'str'},
        'create_time': {'key': 'createTime', 'type': 'iso-8601'},
        'update_time': {'key': 'updateTime', 'type': 'iso-8601'},
        'is_user_created': {'key': 'isUserCreated', 'type': 'bool'},
        'is_auto_created': {'key': 'isAutoCreated', 'type': 'bool'},
        'has_filter': {'key': 'hasFilter', 'type': 'bool'},
        'filter_definition': {'key': 'filterDefinition', 'type': 'str'},
        'col_names': {'key': 'colNames', 'type': '[str]'},
    }

    def __init__(self, compute_account_name=None, version=None, database_name=None, schema_name=None, table_name=None, name=None, user_stat_name=None, stat_data_path=None, create_time=None, update_time=None, is_user_created=None, is_auto_created=None, has_filter=None, filter_definition=None, col_names=None):
        super(USqlTableStatistics, self).__init__(compute_account_name=compute_account_name, version=version)
        self.database_name = database_name
        self.schema_name = schema_name
        self.table_name = table_name
        self.name = name
        self.user_stat_name = user_stat_name
        self.stat_data_path = stat_data_path
        self.create_time = create_time
        self.update_time = update_time
        self.is_user_created = is_user_created
        self.is_auto_created = is_auto_created
        self.has_filter = has_filter
        self.filter_definition = filter_definition
        self.col_names = col_names
