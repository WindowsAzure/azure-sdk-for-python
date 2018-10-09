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


class ChainerSettings(Model):
    """Chainer job settings.

    All required parameters must be populated in order to send to Azure.

    :param python_script_file_path: Required. Python script file path. The
     python script to execute.
    :type python_script_file_path: str
    :param python_interpreter_path: Python interpreter path. The path to the
     Python interpreter.
    :type python_interpreter_path: str
    :param command_line_args: Command line arguments. Command line arguments
     that need to be passed to the python script.
    :type command_line_args: str
    :param process_count: Process count. Number of processes to launch for the
     job execution. The default value for this property is equal to nodeCount
     property
    :type process_count: int
    """

    _validation = {
        'python_script_file_path': {'required': True},
    }

    _attribute_map = {
        'python_script_file_path': {'key': 'pythonScriptFilePath', 'type': 'str'},
        'python_interpreter_path': {'key': 'pythonInterpreterPath', 'type': 'str'},
        'command_line_args': {'key': 'commandLineArgs', 'type': 'str'},
        'process_count': {'key': 'processCount', 'type': 'int'},
    }

    def __init__(self, *, python_script_file_path: str, python_interpreter_path: str=None, command_line_args: str=None, process_count: int=None, **kwargs) -> None:
        super(ChainerSettings, self).__init__(**kwargs)
        self.python_script_file_path = python_script_file_path
        self.python_interpreter_path = python_interpreter_path
        self.command_line_args = command_line_args
        self.process_count = process_count
