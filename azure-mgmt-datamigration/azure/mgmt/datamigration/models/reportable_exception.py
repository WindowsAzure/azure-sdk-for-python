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


class ReportableException(Model):
    """Exception object for all custom exceptions.

    :param message: Error message
    :type message: str
    :param actionable_message: Actionable steps for this exception
    :type actionable_message: str
    :param file_path: The path to the file where exception occurred
    :type file_path: str
    :param line_number: The line number where exception occurred
    :type line_number: str
    :param h_result: Coded numerical value that is assigned to a specific
     exception
    :type h_result: int
    :param stack_trace: Stack trace
    :type stack_trace: str
    """

    _attribute_map = {
        'message': {'key': 'message', 'type': 'str'},
        'actionable_message': {'key': 'actionableMessage', 'type': 'str'},
        'file_path': {'key': 'filePath', 'type': 'str'},
        'line_number': {'key': 'lineNumber', 'type': 'str'},
        'h_result': {'key': 'hResult', 'type': 'int'},
        'stack_trace': {'key': 'stackTrace', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ReportableException, self).__init__(**kwargs)
        self.message = kwargs.get('message', None)
        self.actionable_message = kwargs.get('actionable_message', None)
        self.file_path = kwargs.get('file_path', None)
        self.line_number = kwargs.get('line_number', None)
        self.h_result = kwargs.get('h_result', None)
        self.stack_trace = kwargs.get('stack_trace', None)
