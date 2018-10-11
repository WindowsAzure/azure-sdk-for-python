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


class CustomMpiSettings(Model):
    """Custom MPI job settings.

    All required parameters must be populated in order to send to Azure.

    :param command_line: Required. Command line. The command line to be
     executed by mpi runtime on each compute node.
    :type command_line: str
    :param process_count: Process count. Number of processes to launch for the
     job execution. The default value for this property is equal to nodeCount
     property
    :type process_count: int
    """

    _validation = {
        'command_line': {'required': True},
    }

    _attribute_map = {
        'command_line': {'key': 'commandLine', 'type': 'str'},
        'process_count': {'key': 'processCount', 'type': 'int'},
    }

    def __init__(self, *, command_line: str, process_count: int=None, **kwargs) -> None:
        super(CustomMpiSettings, self).__init__(**kwargs)
        self.command_line = command_line
        self.process_count = process_count
