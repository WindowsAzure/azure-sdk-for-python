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


class OperationStatusPayload(Model):
    """Payload to get the status of an operation.

    All required parameters must be populated in order to send to Azure.

    :param operation_url: Required. The operation url of long running
     operation
    :type operation_url: str
    """

    _validation = {
        'operation_url': {'required': True},
    }

    _attribute_map = {
        'operation_url': {'key': 'operationUrl', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OperationStatusPayload, self).__init__(**kwargs)
        self.operation_url = kwargs.get('operation_url', None)
