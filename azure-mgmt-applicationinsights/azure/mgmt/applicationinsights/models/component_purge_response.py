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


class ComponentPurgeResponse(Model):
    """Response containing operationId for a specific purge action.

    :param operation_id: Id to use when querying for status for a particular
     purge operation.
    :type operation_id: str
    """

    _validation = {
        'operation_id': {'required': True},
    }

    _attribute_map = {
        'operation_id': {'key': 'operationId', 'type': 'str'},
    }

    def __init__(self, operation_id):
        super(ComponentPurgeResponse, self).__init__()
        self.operation_id = operation_id
