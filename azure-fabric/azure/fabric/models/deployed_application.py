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


class DeployedApplication(Model):
    """The application of the deployed.

    :param id:
    :type id: str
    :param name:
    :type name: str
    :param type_name:
    :type type_name: str
    :param status:
    :type status: str
    :param work_directory:
    :type work_directory: str
    :param log_directory:
    :type log_directory: str
    :param temp_directory:
    :type temp_directory: str
    """

    _attribute_map = {
        'id': {'key': 'Id', 'type': 'str'},
        'name': {'key': 'Name', 'type': 'str'},
        'type_name': {'key': 'TypeName', 'type': 'str'},
        'status': {'key': 'Status', 'type': 'str'},
        'work_directory': {'key': 'WorkDirectory', 'type': 'str'},
        'log_directory': {'key': 'LogDirectory', 'type': 'str'},
        'temp_directory': {'key': 'TempDirectory', 'type': 'str'},
    }

    def __init__(self, id=None, name=None, type_name=None, status=None, work_directory=None, log_directory=None, temp_directory=None):
        self.id = id
        self.name = name
        self.type_name = type_name
        self.status = status
        self.work_directory = work_directory
        self.log_directory = log_directory
        self.temp_directory = temp_directory
