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
    """Specifies the settings for CNTK (aka Microsoft Cognitive Toolkit) job.

    :param language_type: Specifies the language type to use for launching
     CNTK (aka Microsoft Cognitive Toolkit) job. Valid values are 'BrainScript'
     or 'Python'.
    :type language_type: str
    :param config_file_path: Specifies the path of the config file. This
     property can be specified only if the languageType is 'BrainScript'.
    :type config_file_path: str
    :param python_script_file_path: The path and file name of the python
     script to execute the job. This property can be specified only if the
     languageType is 'Python'.
    :type python_script_file_path: str
    :param python_interpreter_path: The path to python interpreter. This
     property can be specified only if the languageType is 'Python'.
    :type python_interpreter_path: str
    :param command_line_args: Command line arguments that needs to be passed
     to the python script or CNTK.exe.
    :type command_line_args: str
    :param process_count: Number of processes parameter that is passed to MPI
     runtime. The default value for this property is equal to nodeCount
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

    def __init__(self, **kwargs):
        super(CNTKsettings, self).__init__(**kwargs)
        self.language_type = kwargs.get('language_type', None)
        self.config_file_path = kwargs.get('config_file_path', None)
        self.python_script_file_path = kwargs.get('python_script_file_path', None)
        self.python_interpreter_path = kwargs.get('python_interpreter_path', None)
        self.command_line_args = kwargs.get('command_line_args', None)
        self.process_count = kwargs.get('process_count', None)
