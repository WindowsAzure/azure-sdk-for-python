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


class AutoHealCustomAction(Model):
    """Custom action to be executed
    when an auto heal rule is triggered.

    :param exe: Executable to be run.
    :type exe: str
    :param parameters: Parameters for the executable.
    :type parameters: str
    """

    _attribute_map = {
        'exe': {'key': 'exe', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': 'str'},
    }

    def __init__(self, exe=None, parameters=None):
        self.exe = exe
        self.parameters = parameters
