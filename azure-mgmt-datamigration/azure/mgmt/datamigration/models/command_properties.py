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


class CommandProperties(Model):
    """Base class for all types of DMS command properties. If command is not
    supported by current client, this object is returned.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: MigrateSyncCompleteCommandProperties

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
    """

    _validation = {
        'errors': {'readonly': True},
        'state': {'readonly': True},
        'command_type': {'required': True},
    }

    _attribute_map = {
        'errors': {'key': 'errors', 'type': '[ODataError]'},
        'state': {'key': 'state', 'type': 'str'},
        'command_type': {'key': 'commandType', 'type': 'str'},
    }

    _subtype_map = {
        'command_type': {'Migrate.Sync.Complete.Database': 'MigrateSyncCompleteCommandProperties'}
    }

    def __init__(self, **kwargs):
        super(CommandProperties, self).__init__(**kwargs)
        self.errors = None
        self.state = None
        self.command_type = None
