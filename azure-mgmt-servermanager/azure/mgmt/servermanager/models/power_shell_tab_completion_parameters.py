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


class PowerShellTabCompletionParameters(Model):
    """Collection of parameters for PowerShell tab completion.

    :param command: Command to get tab completion for.
    :type command: str
    """

    _attribute_map = {
        'command': {'key': 'command', 'type': 'str'},
    }

    def __init__(self, command=None):
        self.command = command
