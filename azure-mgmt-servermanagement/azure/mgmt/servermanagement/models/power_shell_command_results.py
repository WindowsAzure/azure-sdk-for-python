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


class PowerShellCommandResults(Model):
    """A collection of results from a PowerShell command.

    :param results:
    :type results:
     list[~azure.mgmt.servermanagement.models.PowerShellCommandResult]
    :param pssession:
    :type pssession: str
    :param command:
    :type command: str
    :param completed:
    :type completed: bool
    """

    _attribute_map = {
        'results': {'key': 'results', 'type': '[PowerShellCommandResult]'},
        'pssession': {'key': 'pssession', 'type': 'str'},
        'command': {'key': 'command', 'type': 'str'},
        'completed': {'key': 'completed', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(PowerShellCommandResults, self).__init__(**kwargs)
        self.results = kwargs.get('results', None)
        self.pssession = kwargs.get('pssession', None)
        self.command = kwargs.get('command', None)
        self.completed = kwargs.get('completed', None)
