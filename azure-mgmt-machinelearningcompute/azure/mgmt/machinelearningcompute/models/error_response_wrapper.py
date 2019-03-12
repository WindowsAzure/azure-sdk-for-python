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


class ErrorResponseWrapper(Model):
    """Wrapper for error response to follow ARM guidelines.

    :param error: The error response.
    :type error: ~azure.mgmt.machinelearningcompute.models.ErrorResponse
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponse'},
    }

    def __init__(self, error=None):
        super(ErrorResponseWrapper, self).__init__()
        self.error = error


class ErrorResponseWrapperException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponseWrapper'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseWrapperException, self).__init__(deserialize, response, 'ErrorResponseWrapper', *args)
