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


class MigrateMySqlAzureDbForMySqlSyncDatabaseInput(Model):
    """Database specific information for MySQL to Azure Database for MySQL
    migration task inputs.

    :param name: Name of the database
    :type name: str
    :param target_database_name: Name of target database. Note: Target
     database will be truncated before starting migration.
    :type target_database_name: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'target_database_name': {'key': 'targetDatabaseName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(MigrateMySqlAzureDbForMySqlSyncDatabaseInput, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.target_database_name = kwargs.get('target_database_name', None)
