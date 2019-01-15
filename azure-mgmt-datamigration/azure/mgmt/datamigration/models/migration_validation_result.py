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


class MigrationValidationResult(Model):
    """Migration Validation Result.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Migration validation result identifier
    :vartype id: str
    :ivar migration_id: Migration Identifier
    :vartype migration_id: str
    :param summary_results: Validation summary results for each database
    :type summary_results: dict[str,
     ~azure.mgmt.datamigration.models.MigrationValidationDatabaseSummaryResult]
    :ivar status: Current status of validation at the migration level. Status
     from the database validation result status will be aggregated here.
     Possible values include: 'Default', 'NotStarted', 'Initialized',
     'InProgress', 'Completed', 'CompletedWithIssues', 'Stopped', 'Failed'
    :vartype status: str or ~azure.mgmt.datamigration.models.ValidationStatus
    """

    _validation = {
        'id': {'readonly': True},
        'migration_id': {'readonly': True},
        'status': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'migration_id': {'key': 'migrationId', 'type': 'str'},
        'summary_results': {'key': 'summaryResults', 'type': '{MigrationValidationDatabaseSummaryResult}'},
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(MigrationValidationResult, self).__init__(**kwargs)
        self.id = None
        self.migration_id = None
        self.summary_results = kwargs.get('summary_results', None)
        self.status = None
