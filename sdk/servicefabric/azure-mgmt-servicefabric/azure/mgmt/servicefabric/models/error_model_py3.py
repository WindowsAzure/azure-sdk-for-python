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


class ErrorModel(Model):
    """The structure of the error.

    :param error: The error details.
    :type error: ~azure.mgmt.servicefabric.models.ErrorModelError
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorModelError'},
    }

    def __init__(self, *, error=None, **kwargs) -> None:
        super(ErrorModel, self).__init__(**kwargs)
        self.error = error


class ErrorModelException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorModel'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorModelException, self).__init__(deserialize, response, 'ErrorModel', *args)
