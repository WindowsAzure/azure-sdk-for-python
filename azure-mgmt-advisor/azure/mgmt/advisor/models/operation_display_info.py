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


class OperationDisplayInfo(Model):
    """The operation supported by Advisor.

    :param description: The description of the operation.
    :type description: str
    :param operation: The action that users can perform, based on their
     permission level.
    :type operation: str
    :param provider: Service provider: Microsoft Advisor.
    :type provider: str
    :param resource: Resource on which the operation is performed.
    :type resource: str
    """

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
    }

    def __init__(self, description=None, operation=None, provider=None, resource=None):
        super(OperationDisplayInfo, self).__init__()
        self.description = description
        self.operation = operation
        self.provider = provider
        self.resource = resource
