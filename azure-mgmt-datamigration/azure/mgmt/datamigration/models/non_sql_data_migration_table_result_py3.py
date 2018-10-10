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


class NonSqlDataMigrationTableResult(Model):
    """Object used to report the data migration results of a table.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar result_code: Result code of the data migration. Possible values
     include: 'Initial', 'Completed', 'ObjectNotExistsInSource',
     'ObjectNotExistsInTarget', 'TargetObjectIsInaccessible', 'FatalError'
    :vartype result_code: str or
     ~azure.mgmt.datamigration.models.DataMigrationResultCode
    :ivar source_name: Name of the source table
    :vartype source_name: str
    :ivar target_name: Name of the target table
    :vartype target_name: str
    :ivar source_row_count: Number of rows in the source table
    :vartype source_row_count: long
    :ivar target_row_count: Number of rows in the target table
    :vartype target_row_count: long
    :ivar elapsed_time_in_miliseconds: Time taken to migrate the data
    :vartype elapsed_time_in_miliseconds: float
    :ivar errors: List of errors, if any, during migration
    :vartype errors: list[~azure.mgmt.datamigration.models.DataMigrationError]
    """

    _validation = {
        'result_code': {'readonly': True},
        'source_name': {'readonly': True},
        'target_name': {'readonly': True},
        'source_row_count': {'readonly': True},
        'target_row_count': {'readonly': True},
        'elapsed_time_in_miliseconds': {'readonly': True},
        'errors': {'readonly': True},
    }

    _attribute_map = {
        'result_code': {'key': 'resultCode', 'type': 'str'},
        'source_name': {'key': 'sourceName', 'type': 'str'},
        'target_name': {'key': 'targetName', 'type': 'str'},
        'source_row_count': {'key': 'sourceRowCount', 'type': 'long'},
        'target_row_count': {'key': 'targetRowCount', 'type': 'long'},
        'elapsed_time_in_miliseconds': {'key': 'elapsedTimeInMiliseconds', 'type': 'float'},
        'errors': {'key': 'errors', 'type': '[DataMigrationError]'},
    }

    def __init__(self, **kwargs) -> None:
        super(NonSqlDataMigrationTableResult, self).__init__(**kwargs)
        self.result_code = None
        self.source_name = None
        self.target_name = None
        self.source_row_count = None
        self.target_row_count = None
        self.elapsed_time_in_miliseconds = None
        self.errors = None
