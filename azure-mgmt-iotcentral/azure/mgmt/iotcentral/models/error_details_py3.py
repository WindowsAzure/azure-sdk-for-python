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


class ErrorDetails(Model):
    """Error details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar target: The target of the particular error.
    :vartype target: str
    :param details: A list of additional details about the error.
    :type details: list[~azure.mgmt.iotcentral.models.ErrorResponseBody]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'target': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'error.code', 'type': 'str'},
        'message': {'key': 'error.message', 'type': 'str'},
        'target': {'key': 'error.target', 'type': 'str'},
        'details': {'key': 'error.details', 'type': '[ErrorResponseBody]'},
    }

    def __init__(self, *, details=None, **kwargs) -> None:
        super(ErrorDetails, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.details = details


class ErrorDetailsException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorDetails'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorDetailsException, self).__init__(deserialize, response, 'ErrorDetails', *args)
