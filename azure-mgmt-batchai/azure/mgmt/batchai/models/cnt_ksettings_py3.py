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


class CNTKsettings(Model):
    """CNTK (aka Microsoft Cognitive Toolkit) job settings.

    :param language_type: Language type. The language to use for launching
     CNTK (aka Microsoft Cognitive Toolkit) job. Valid values are 'BrainScript'
     or 'Python'.
    :type language_type: str
    :param config_file_path: Config file path. Specifies the path of the
     BrainScript config file. This property can be specified only if the
     languageType is 'BrainScript'.
    :type config_file_path: str
    :param python_script_file_path: Python script file path. Python script to
     execute. This property can be specified only if the languageType is
     'Python'.
    :type python_script_file_path: str
    :param python_interpreter_path: Python interpreter path. The path to the
     Python interpreter. This property can be specified only if the
     languageType is 'Python'.
    :type python_interpreter_path: str
    :param command_line_args: Command line arguments. Command line arguments
     that need to be passed to the python script or cntk executable.
    :type command_line_args: str
    :param process_count: Process count. Number of processes to launch for the
     job execution. The default value for this property is equal to nodeCount
     property
    :type process_count: int
    """

    _attribute_map = {
        'language_type': {'key': 'languageType', 'type': 'str'},
        'config_file_path': {'key': 'configFilePath', 'type': 'str'},
        'python_script_file_path': {'key': 'pythonScriptFilePath', 'type': 'str'},
        'python_interpreter_path': {'key': 'pythonInterpreterPath', 'type': 'str'},
        'command_line_args': {'key': 'commandLineArgs', 'type': 'str'},
        'process_count': {'key': 'processCount', 'type': 'int'},
    }

    def __init__(self, *, language_type: str=None, config_file_path: str=None, python_script_file_path: str=None, python_interpreter_path: str=None, command_line_args: str=None, process_count: int=None, **kwargs) -> None:
        super(CNTKsettings, self).__init__(**kwargs)
        self.language_type = language_type
        self.config_file_path = config_file_path
        self.python_script_file_path = python_script_file_path
        self.python_interpreter_path = python_interpreter_path
        self.command_line_args = command_line_args
        self.process_count = process_count
