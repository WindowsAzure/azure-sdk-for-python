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


class GraphError(Model):
    """Active Directory error information.

    :param code: Error code.
    :type code: str
    :param message: Error message value.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'odata\\.error.code', 'type': 'str'},
        'message': {'key': 'odata\\.error.message.value', 'type': 'str'},
    }

    def __init__(self, code=None, message=None):
        self.code = code
        self.message = message


class GraphErrorException(HttpOperationError):
    """Server responsed with exception of type: 'GraphError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(GraphErrorException, self).__init__(deserialize, response, 'GraphError', *args)
