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

from .response import Response
from msrest.exceptions import HttpOperationError


class ErrorResponse(Response):
    """The top-level response that represents a failed request.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param _type: Required. Constant filled by server.
    :type _type: str
    :ivar id: A String identifier.
    :vartype id: str
    :param errors: Required. A list of errors that describe the reasons why
     the request failed.
    :type errors:
     list[~azure.cognitiveservices.language.spellcheck.models.Error]
    """

    _validation = {
        '_type': {'required': True},
        'id': {'readonly': True},
        'errors': {'required': True},
    }

    _attribute_map = {
        '_type': {'key': '_type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'errors': {'key': 'errors', 'type': '[Error]'},
    }

    def __init__(self, *, errors, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.errors = errors
        self._type = 'ErrorResponse'


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)
