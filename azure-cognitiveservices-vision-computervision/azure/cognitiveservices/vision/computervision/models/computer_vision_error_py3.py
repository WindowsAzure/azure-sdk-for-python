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
from msrest.exceptions import HttpOperationError


class ComputerVisionError(Model):
    """Details about the API request error.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. The error code.
    :type code: object
    :param message: Required. A message explaining the error reported by the
     service.
    :type message: str
    :param request_id: A unique request identifier.
    :type request_id: str
    """

    _validation = {
        'code': {'required': True},
        'message': {'required': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'object'},
        'message': {'key': 'message', 'type': 'str'},
        'request_id': {'key': 'requestId', 'type': 'str'},
    }

    def __init__(self, *, code, message: str, request_id: str=None, **kwargs) -> None:
        super(ComputerVisionError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.request_id = request_id


class ComputerVisionErrorException(HttpOperationError):
    """Server responsed with exception of type: 'ComputerVisionError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ComputerVisionErrorException, self).__init__(deserialize, response, 'ComputerVisionError', *args)
