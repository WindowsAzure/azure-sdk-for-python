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


class HorovodSettings(Model):
    """Specifies the settings for Horovod job.

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

    def __init__(self, **kwargs):
        super(HorovodSettings, self).__init__(**kwargs)
        self.python_script_file_path = kwargs.get('python_script_file_path', None)
        self.python_interpreter_path = kwargs.get('python_interpreter_path', None)
        self.command_line_args = kwargs.get('command_line_args', None)
        self.process_count = kwargs.get('process_count', None)
