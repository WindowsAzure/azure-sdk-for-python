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


class GetUserTablesSqlSyncTaskInput(Model):
    """Input for the task that collects user tables for the given list of
    databases.

    All required parameters must be populated in order to send to Azure.

    :param source_connection_info: Required. Connection information for SQL
     Server
    :type source_connection_info:
     ~azure.mgmt.datamigration.models.SqlConnectionInfo
    :param target_connection_info: Required. Connection information for SQL DB
    :type target_connection_info:
     ~azure.mgmt.datamigration.models.SqlConnectionInfo
    :param selected_source_databases: Required. List of source database names
     to collect tables for
    :type selected_source_databases: list[str]
    :param selected_target_databases: Required. List of target database names
     to collect tables for
    :type selected_target_databases: list[str]
    """

    _validation = {
        'source_connection_info': {'required': True},
        'target_connection_info': {'required': True},
        'selected_source_databases': {'required': True},
        'selected_target_databases': {'required': True},
    }

    _attribute_map = {
        'source_connection_info': {'key': 'sourceConnectionInfo', 'type': 'SqlConnectionInfo'},
        'target_connection_info': {'key': 'targetConnectionInfo', 'type': 'SqlConnectionInfo'},
        'selected_source_databases': {'key': 'selectedSourceDatabases', 'type': '[str]'},
        'selected_target_databases': {'key': 'selectedTargetDatabases', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(GetUserTablesSqlSyncTaskInput, self).__init__(**kwargs)
        self.source_connection_info = kwargs.get('source_connection_info', None)
        self.target_connection_info = kwargs.get('target_connection_info', None)
        self.selected_source_databases = kwargs.get('selected_source_databases', None)
        self.selected_target_databases = kwargs.get('selected_target_databases', None)
