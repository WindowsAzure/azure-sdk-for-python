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


class OperationDisplay(Model):
    """The object that describes the operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provider: The friendly name of the resource provider.
    :vartype provider: str
    :ivar operation: The operation type: read, write, delete, listKeys/action,
     etc.
    :vartype operation: str
    :ivar resource: The resource type on which the operation is performed.
    :vartype resource: str
    :ivar description: The friendly name of the operation.
    :vartype description: str
    """

    _validation = {
        'provider': {'readonly': True},
        'operation': {'readonly': True},
        'resource': {'readonly': True},
        'description': {'readonly': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self):
        super(OperationDisplay, self).__init__()
        self.provider = None
        self.operation = None
        self.resource = None
        self.description = None
