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

from .command_properties import CommandProperties


class MigrateSyncCompleteCommandProperties(CommandProperties):
    """Properties for the command that completes sync migration for a database.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar errors: Array of errors. This is ignored if submitted.
    :vartype errors: list[~azure.mgmt.datamigration.models.ODataError]
    :ivar state: The state of the command. This is ignored if submitted.
     Possible values include: 'Unknown', 'Accepted', 'Running', 'Succeeded',
     'Failed'
    :vartype state: str or ~azure.mgmt.datamigration.models.CommandState
    :param command_type: Required. Constant filled by server.
    :type command_type: str
    :param input: Command input
    :type input:
     ~azure.mgmt.datamigration.models.MigrateSyncCompleteCommandInput
    :ivar output: Command output. This is ignored if submitted.
    :vartype output:
     ~azure.mgmt.datamigration.models.MigrateSyncCompleteCommandOutput
    """

    _validation = {
        'errors': {'readonly': True},
        'state': {'readonly': True},
        'command_type': {'required': True},
        'output': {'readonly': True},
    }

    _attribute_map = {
        'errors': {'key': 'errors', 'type': '[ODataError]'},
        'state': {'key': 'state', 'type': 'str'},
        'command_type': {'key': 'commandType', 'type': 'str'},
        'input': {'key': 'input', 'type': 'MigrateSyncCompleteCommandInput'},
        'output': {'key': 'output', 'type': 'MigrateSyncCompleteCommandOutput'},
    }

    def __init__(self, **kwargs):
        super(MigrateSyncCompleteCommandProperties, self).__init__(**kwargs)
        self.input = kwargs.get('input', None)
        self.output = None
        self.command_type = 'Migrate.Sync.Complete.Database'
