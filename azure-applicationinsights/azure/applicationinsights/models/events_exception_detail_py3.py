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


class EventsExceptionDetail(Model):
    """Exception details.

    :param severity_level: The severity level of the exception detail
    :type severity_level: str
    :param outer_id: The outer ID of the exception detail
    :type outer_id: str
    :param message: The message of the exception detail
    :type message: str
    :param type: The type of the exception detail
    :type type: str
    :param id: The ID of the exception detail
    :type id: str
    :param parsed_stack: The parsed stack
    :type parsed_stack:
     list[~azure.applicationinsights.models.EventsExceptionDetailsParsedStack]
    """

    _attribute_map = {
        'severity_level': {'key': 'severityLevel', 'type': 'str'},
        'outer_id': {'key': 'outerId', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'parsed_stack': {'key': 'parsedStack', 'type': '[EventsExceptionDetailsParsedStack]'},
    }

    def __init__(self, *, severity_level: str=None, outer_id: str=None, message: str=None, type: str=None, id: str=None, parsed_stack=None, **kwargs) -> None:
        super(EventsExceptionDetail, self).__init__(**kwargs)
        self.severity_level = severity_level
        self.outer_id = outer_id
        self.message = message
        self.type = type
        self.id = id
        self.parsed_stack = parsed_stack
