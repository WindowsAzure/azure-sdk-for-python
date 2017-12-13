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


class Error(Model):
    """Defines the error that occurred.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param code: The error code that identifies the category of error.
     Possible values include: 'None', 'ServerError', 'InvalidRequest',
     'RateLimitExceeded', 'InvalidAuthorization', 'InsufficientAuthorization'.
     Default value: "None" .
    :type code: str or
     ~azure.cognitiveservices.search.newssearch.models.ErrorCode
    :ivar sub_code: The error code that further helps to identify the error.
     Possible values include: 'UnexpectedError', 'ResourceError',
     'NotImplemented', 'ParameterMissing', 'ParameterInvalidValue',
     'HttpNotAllowed', 'Blocked', 'AuthorizationMissing',
     'AuthorizationRedundancy', 'AuthorizationDisabled', 'AuthorizationExpired'
    :vartype sub_code: str or
     ~azure.cognitiveservices.search.newssearch.models.ErrorSubCode
    :param message: A description of the error.
    :type message: str
    :ivar more_details: A description that provides additional information
     about the error.
    :vartype more_details: str
    :ivar parameter: The parameter in the request that caused the error.
    :vartype parameter: str
    :ivar value: The parameter's value in the request that was not valid.
    :vartype value: str
    """

    _validation = {
        'code': {'required': True},
        'sub_code': {'readonly': True},
        'message': {'required': True},
        'more_details': {'readonly': True},
        'parameter': {'readonly': True},
        'value': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'sub_code': {'key': 'subCode', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'more_details': {'key': 'moreDetails', 'type': 'str'},
        'parameter': {'key': 'parameter', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, message, code="None"):
        self.code = code
        self.sub_code = None
        self.message = message
        self.more_details = None
        self.parameter = None
        self.value = None
