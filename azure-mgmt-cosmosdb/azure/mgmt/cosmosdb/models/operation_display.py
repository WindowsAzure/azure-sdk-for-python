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
    """The object that represents the operation.

    :param provider: Service provider: Microsoft.ResourceProvider
    :type provider: str
    :param resource: Resource on which the operation is performed: Profile,
     endpoint, etc.
    :type resource: str
    :param operation: Operation type: Read, write, delete, etc.
    :type operation: str
    :param description: Description of operation
    :type description: str
    """

    _attribute_map = {
        'provider': {'key': 'Provider', 'type': 'str'},
        'resource': {'key': 'Resource', 'type': 'str'},
        'operation': {'key': 'Operation', 'type': 'str'},
        'description': {'key': 'Description', 'type': 'str'},
    }

    def __init__(self, provider=None, resource=None, operation=None, description=None):
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description
