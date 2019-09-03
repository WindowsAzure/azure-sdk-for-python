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
    """Properties of the operation.

    :param description: Description of the operation
    :type description: str
    :param operation: Operation name
    :type operation: str
    :param provider: Provider name
    :type provider: str
    :param resource: Resource name
    :type resource: str
    """

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OperationDisplay, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.operation = kwargs.get('operation', None)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
