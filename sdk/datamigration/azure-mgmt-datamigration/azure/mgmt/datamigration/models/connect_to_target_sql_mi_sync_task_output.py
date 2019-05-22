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


class ConnectToTargetSqlMISyncTaskOutput(Model):
    """Output for the task that validates connection to Azure SQL Database Managed
    Instance.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar target_server_version: Target server version
    :vartype target_server_version: str
    :ivar target_server_brand_version: Target server brand version
    :vartype target_server_brand_version: str
    :ivar validation_errors: Validation errors
    :vartype validation_errors:
     list[~azure.mgmt.datamigration.models.ReportableException]
    """

    _validation = {
        'target_server_version': {'readonly': True},
        'target_server_brand_version': {'readonly': True},
        'validation_errors': {'readonly': True},
    }

    _attribute_map = {
        'target_server_version': {'key': 'targetServerVersion', 'type': 'str'},
        'target_server_brand_version': {'key': 'targetServerBrandVersion', 'type': 'str'},
        'validation_errors': {'key': 'validationErrors', 'type': '[ReportableException]'},
    }

    def __init__(self, **kwargs):
        super(ConnectToTargetSqlMISyncTaskOutput, self).__init__(**kwargs)
        self.target_server_version = None
        self.target_server_brand_version = None
        self.validation_errors = None
