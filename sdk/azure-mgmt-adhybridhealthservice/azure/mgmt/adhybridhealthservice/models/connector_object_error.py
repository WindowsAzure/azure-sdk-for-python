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


class ConnectorObjectError(Model):
    """The connector object error.

    :param id: The error Id.
    :type id: str
    :param run_step_result_id: The run step result Id.
    :type run_step_result_id: str
    :param connector_id: The connector Id.
    :type connector_id: str
    :param type: The type of error.
    :type type: str
    :param error_code: The error code.
    :type error_code: str
    :param message: The message for the object error.
    :type message: str
    :param entry_number: The entry number for object error occurred.
    :type entry_number: int
    :param line_number: The line number for the object error.
    :type line_number: int
    :param column_number: The column number for the object error.
    :type column_number: int
    :param dn: The distinguished name of the object.
    :type dn: str
    :param anchor: The name for the anchor of the object.
    :type anchor: str
    :param attribute_name: The attribute name of the object.
    :type attribute_name: str
    :param server_error_detail: The server side error details.
    :type server_error_detail: str
    :param values: The value corresponding to attribute name.
    :type values: list[str]
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'run_step_result_id': {'key': 'runStepResultId', 'type': 'str'},
        'connector_id': {'key': 'connectorId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'error_code': {'key': 'errorCode', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'entry_number': {'key': 'entryNumber', 'type': 'int'},
        'line_number': {'key': 'lineNumber', 'type': 'int'},
        'column_number': {'key': 'columnNumber', 'type': 'int'},
        'dn': {'key': 'dn', 'type': 'str'},
        'anchor': {'key': 'anchor', 'type': 'str'},
        'attribute_name': {'key': 'attributeName', 'type': 'str'},
        'server_error_detail': {'key': 'serverErrorDetail', 'type': 'str'},
        'values': {'key': 'values', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ConnectorObjectError, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.run_step_result_id = kwargs.get('run_step_result_id', None)
        self.connector_id = kwargs.get('connector_id', None)
        self.type = kwargs.get('type', None)
        self.error_code = kwargs.get('error_code', None)
        self.message = kwargs.get('message', None)
        self.entry_number = kwargs.get('entry_number', None)
        self.line_number = kwargs.get('line_number', None)
        self.column_number = kwargs.get('column_number', None)
        self.dn = kwargs.get('dn', None)
        self.anchor = kwargs.get('anchor', None)
        self.attribute_name = kwargs.get('attribute_name', None)
        self.server_error_detail = kwargs.get('server_error_detail', None)
        self.values = kwargs.get('values', None)
